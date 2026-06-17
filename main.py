from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os
import time
import logging
import jwt
from jwt import PyJWKClient
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("wakeai-proxy")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"

# Supabase JWT verification (LOG-ONLY mode — verify and log, never reject yet).
# Supabase signs tokens with ES256 (asymmetric), so we verify against the project's
# public keys served at its JWKS endpoint. Configure via either the full JWKS URL or
# the project ref. PyJWKClient is created once and caches keys internally.
SUPABASE_JWKS_URL = os.environ.get("SUPABASE_JWKS_URL")
SUPABASE_PROJECT_REF = os.environ.get("SUPABASE_PROJECT_REF")
if not SUPABASE_JWKS_URL and SUPABASE_PROJECT_REF:
    SUPABASE_JWKS_URL = (
        f"https://{SUPABASE_PROJECT_REF}.supabase.co/auth/v1/.well-known/jwks.json"
    )

jwks_client = None
if SUPABASE_JWKS_URL:
    jwks_client = PyJWKClient(SUPABASE_JWKS_URL)
else:
    logger.warning(
        "Neither SUPABASE_JWKS_URL nor SUPABASE_PROJECT_REF is set — JWT verification "
        "will be skipped (log-only mode still active, requests are NOT blocked)."
    )


def verify_token_log_only(request: Request) -> None:
    """LOG-ONLY: verify the Supabase JWT on the request and log the outcome.

    Never raises and never blocks — this stage only observes so we can confirm
    real tokens are arriving correctly before enforcing in a later stage.
    """
    auth_header = request.headers.get("authorization")
    if not auth_header:
        logger.info("JWT log-only: no Authorization header present")
        return

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        logger.info("JWT log-only: malformed Authorization header (expected 'Bearer <token>')")
        return

    token = parts[1]

    # Diagnostic: log the token's UNVERIFIED header so we can see the actual
    # signing algorithm (e.g. ES256/RS256 vs HS256). This does not verify the
    # signature — it only reads the header — and never blocks the request.
    try:
        header = jwt.get_unverified_header(token)
        logger.info("JWT log-only: token alg: %s (header: %s)", header.get("alg"), header)
    except Exception as exc:
        logger.info("JWT log-only: could not read token header (%s)", type(exc).__name__)

    if jwks_client is None:
        logger.warning("JWT log-only: token present but JWKS not configured — cannot verify")
        return

    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["ES256"],
            audience="authenticated",
            leeway=30,
        )
        logger.info("JWT log-only: token VERIFIED for sub=%s", claims.get("sub"))
    except jwt.ExpiredSignatureError:
        logger.info("JWT log-only: token verification FAILED — expired")
    except jwt.InvalidTokenError as exc:
        logger.info("JWT log-only: token verification FAILED — invalid (%s)", type(exc).__name__)
    except Exception as exc:
        # PyJWKClient can raise on JWKS fetch / kid lookup failures; stay non-blocking.
        logger.info("JWT log-only: token verification FAILED — jwks error (%s)", type(exc).__name__)

# Rate limiting — 10 requests per minute per user
rate_limit_store = defaultdict(list)
RATE_LIMIT = 10
RATE_WINDOW = 60

def check_rate_limit(user_id: str) -> bool:
    now = time.time()
    requests = rate_limit_store[user_id]
    rate_limit_store[user_id] = [t for t in requests if now - t < RATE_WINDOW]
    if len(rate_limit_store[user_id]) >= RATE_LIMIT:
        return False
    rate_limit_store[user_id].append(now)
    return True

@app.get("/health")
async def health():
    return {"status": "ok"}

@app.post("/chat")
async def chat(request: Request):
    if not ANTHROPIC_API_KEY:
        raise HTTPException(status_code=500, detail="API key not configured")

    # LOG-ONLY: observe Supabase JWT verification without enforcing it yet.
    verify_token_log_only(request)

    body = await request.json()

    # Extract user_id for rate limiting then remove before forwarding to Anthropic
    user_id = body.pop("user_id", None) or request.client.host
    if not check_rate_limit(user_id):
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please wait a moment before sending another message."
        )

    async with httpx.AsyncClient(timeout=30.0) as client:
        response = await client.post(
            ANTHROPIC_URL,
            headers={
                "Content-Type": "application/json",
                "anthropic-version": "2023-06-01",
                "x-api-key": ANTHROPIC_API_KEY,
            },
            json=body
        )

    return response.json()
