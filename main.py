from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
import httpx
import os
import time
from collections import defaultdict

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"

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
