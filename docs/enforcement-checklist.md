# JWT enforcement checklist

`verify_token_log_only` in `main.py` currently verifies Supabase JWTs and logs the outcome
without ever rejecting a request. The `sub` it returns only selects a rate-limit bucket, so a
token that fails verification costs the caller nothing but a coarser bucket. The moment that
outcome gates access, several things that are inert today become load-bearing. This is the list
of what has to change first.

## Before flipping to enforcement

### 1. Require `exp` explicitly and pin the issuer

`jwt.decode` verifies `exp` only when the claim is present, and does not check `iss` at all
unless asked. Add both:

```python
claims = jwt.decode(
    token,
    signing_key.key,
    algorithms=["ES256"],
    audience="authenticated",
    issuer=f"https://{SUPABASE_PROJECT_REF}.supabase.co/auth/v1",
    options={"require": ["exp"]},
    leeway=30,
)
```

Neither is attacker-reachable today: key material is already pinned to one project's JWKS, so a
token signed by anyone else fails the signature check regardless. But once verification decides
whether a request is served, a Supabase-signed token that omits `exp` would be valid forever,
and the issuer check is the thing that keeps that guarantee tied to *our* project rather than to
whatever JWKS URL the environment happens to hold.

Pinning the issuer means the fallback that derives `SUPABASE_JWKS_URL` from `SUPABASE_PROJECT_REF`
and the direct `SUPABASE_JWKS_URL` override need to agree on the project. Prefer deriving both the
JWKS URL and the expected issuer from `SUPABASE_PROJECT_REF`, and treat a bare `SUPABASE_JWKS_URL`
with no ref as a configuration error at enforcement time rather than a silent skip.

### 2. Decide the policy on anonymous sign-ins — explicitly

Supabase anonymous sign-ins produce a fully valid ES256 token with `aud=authenticated`, so they
already land in the `"verified"` branch. They are legitimate users and almost certainly stay
allowed; the point is that this should be a stated decision rather than a side effect of the
audience check.

Whichever way it goes, make it visible in the code: read `is_anonymous` (or `role`) off the
claims and branch on it, even if the branch is `# anonymous sessions are allowed`. Otherwise the
next person to tighten the audience check silently changes who can use the product.

### 3. Readiness signal: wait for `absent` and `legacy` to dry up

The `chat-auth` log line exists to answer exactly one question — how much live traffic would
enforcement break. Flip only when the tail has gone quiet:

- `verify=absent` — no `Authorization` header at all. Pre-login builds, and anything else that
  never learned to send a token.
- `legacy_user_id=True` — identifies pre-login builds *specifically*, since only those versions
  still put `user_id` in the request body. This is the sharper of the two signals: `absent` can
  also mean a current build whose session expired, while `legacy_user_id=True` is an unambiguous
  old-binary fingerprint.
- `verify=unverifiable-no-jwks` — configuration is broken, not the client. Fix before flipping;
  enforcing in this state rejects everyone.

`expired` and `invalid-*` are expected to persist at some low rate and are not blockers — those
are the requests enforcement is *supposed* to reject.

Consider a staged flip rather than a single switch: reject `malformed` and `invalid-*` first,
keep serving `absent` for one release, then close it.

## Known, accepted: upstream errors are relayed as HTTP 200

`main.py:215` returns `response.json()` unconditionally, so an Anthropic non-2xx — rate limit,
overload, invalid request — reaches the client as a 200 with the error body inline. A security
review flagged this and did not fault it: the relayed body was confirmed to carry no server-side
secret, no API key, and no org identifier.

It is worth knowing anyway, because it masks upstream failures from the client. The app cannot
distinguish "the model answered" from "Anthropic refused" by status code alone, and any
client-side retry or error handling keyed on HTTP status will not fire. If that becomes a
problem, forward `response.status_code` alongside the body rather than adding a translation
layer — the pass-through is the useful property here.
