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

# Server-side bounds on what the proxy will relay. The proxy URL ships inside
# the app binary, so the request body must be treated as attacker-controlled.
#
# max_tokens is CLAMPED (not rejected): live app versions send 800 today and
# 2000 imminently, so a cap degrades gracefully while a rejection would break
# chat. 4096 = 2x headroom over the imminent 2000 so the next app-side bump
# needs no proxy change, while bounding worst-case output spend per request.
MAX_TOKENS_CEILING = 4096

# Models are ALLOWLISTED (rejected, not coerced): only ids the app has ever
# shipped. claude-sonnet-4-5 is every released version; claude-sonnet-4-20250514
# existed for one day of development (Apr 28-29) and almost certainly never
# shipped, but permitting it is free and guarantees no live client breaks.
ALLOWED_MODELS = {
    "claude-sonnet-4-5",
    "claude-sonnet-4-20250514",
}

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


def verify_token_log_only(request: Request):
    """LOG-ONLY: verify the Supabase JWT on the request without enforcing it.

    Returns (token_present, outcome, sub). outcome is one of:
    "absent", "malformed", "unverifiable-no-jwks", "verified", "expired",
    "invalid-<ErrorName>", "jwks-error-<ErrorName>".

    Never raises and never blocks — app versions predating the login system
    send no token at all, so enforcement would silently break their chat.
    The caller logs one structured line per request so verified-vs-absent
    traffic can be measured from Railway logs before flipping to enforcement.
    """
    auth_header = request.headers.get("authorization")
    if not auth_header:
        return False, "absent", None

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return True, "malformed", None

    token = parts[1]

    if jwks_client is None:
        return True, "unverifiable-no-jwks", None

    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["ES256"],
            audience="authenticated",
            leeway=30,
        )
        return True, "verified", claims.get("sub")
    except jwt.ExpiredSignatureError:
        return True, "expired", None
    except jwt.InvalidTokenError as exc:
        return True, "invalid-" + type(exc).__name__, None
    except Exception as exc:
        # PyJWKClient can raise on JWKS fetch / kid lookup failures; stay non-blocking.
        return True, "jwks-error-" + type(exc).__name__, None

# Rate limiting — 10 requests per minute per key (see the key derivation in
# /chat: verified JWT sub, else legacy body user_id, else client IP, else peer)
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
    token_present, verify_outcome, token_sub = verify_token_log_only(request)

    body = await request.json()

    # Pop user_id before forwarding to Anthropic. Only pre-login app versions
    # still send it; its presence is a version signal.
    body_user_id = body.pop("user_id", None)

    # Rate-limit key, best available first. Using sub is NOT enforcement: a
    # missing or failed token never rejects, it just falls to the next key.
    #   1. verified JWT sub  — true per-user key (all current app versions)
    #   2. legacy body user_id — pre-login versions, behaviour unchanged
    #   3. x-forwarded-for   — real client IP; read directly from the header,
    #      so it needs no uvicorn forwarded-allow-ips config. RIGHTMOST entry:
    #      that hop is appended by Railway's edge and can't be forged by a
    #      client-supplied header, unlike the leftmost.
    #   4. request.client.host — last resort (Railway's edge peer, shared)
    xff = request.headers.get("x-forwarded-for", "")
    xff_ip = xff.rsplit(",", 1)[-1].strip() if xff else ""
    if verify_outcome == "verified" and token_sub:
        rl_kind, rl_key = "sub", "sub:" + str(token_sub)
    elif body_user_id:
        rl_kind, rl_key = "legacy", "legacy:" + str(body_user_id)
    elif xff_ip:
        rl_kind, rl_key = "xff", "ip:" + xff_ip
    else:
        rl_kind, rl_key = "peer", "peer:" + (request.client.host if request.client else "unknown")

    model = body.get("model")
    requested_max_tokens = body.get("max_tokens")
    clamped = False
    if (
        isinstance(requested_max_tokens, (int, float))
        and not isinstance(requested_max_tokens, bool)
        and requested_max_tokens > MAX_TOKENS_CEILING
    ):
        body["max_tokens"] = MAX_TOKENS_CEILING
        clamped = True

    # One structured line per request, BEFORE the rate-limit gate so 429'd
    # traffic still appears in the corpus. The User-Agent is the only
    # app-version signal available (URLSession default: "WakeAI(G)/<build>
    # CFNetwork/.. Darwin/.."); x-forwarded-for is the real client IP on Railway.
    logger.info(
        'chat-auth: token_present=%s verify=%s sub=%s rl_key=%s model=%s '
        'max_tokens=%s clamped=%s legacy_user_id=%s ua="%s" xff="%s"',
        token_present,
        verify_outcome,
        token_sub,
        rl_kind,
        model,
        requested_max_tokens,
        clamped,
        body_user_id is not None,
        request.headers.get("user-agent", "-"),
        xff or "-",
    )

    if not check_rate_limit(rl_key):
        raise HTTPException(
            status_code=429,
            detail="Chat is busy right now. Please wait a moment and try again."
        )

    if not isinstance(model, str) or model not in ALLOWED_MODELS:
        logger.warning("chat: rejected disallowed model %r", model)
        raise HTTPException(
            status_code=400,
            detail=f"Model '{model}' is not supported by this service."
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
