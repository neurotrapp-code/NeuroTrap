"""JWT authentication for the management API (Day 31).

Single admin account from env (``ADMIN_USER`` / ``ADMIN_PASS``); password is
compared in constant time. Tokens are signed with ``JWT_SECRET`` (HS256) and
expire after ``JWT_TTL_MIN`` minutes. The ``@require_auth`` decorator guards REST
endpoints; the WebSocket validates the token from its query string.
"""
from __future__ import annotations

import hmac
import os
import time
from functools import wraps

import jwt
from flask import g, jsonify, request

# Read config at call time (not import time) so env set by the launcher/tests is
# always honoured and behaviour never depends on import order.
_EPHEMERAL_SECRET = None


def _secret() -> str:
    """JWT signing key from JWT_SECRET, or a stable per-process random fallback."""
    global _EPHEMERAL_SECRET
    s = os.environ.get("JWT_SECRET", "")
    if s:
        return s
    if _EPHEMERAL_SECRET is None:
        _EPHEMERAL_SECRET = os.urandom(32).hex()
    return _EPHEMERAL_SECRET


def _ttl_min() -> int:
    return int(os.environ.get("JWT_TTL_MIN", "120"))


def check_credentials(username: str, password: str) -> bool:
    admin_user = os.environ.get("ADMIN_USER", "admin")
    admin_pass = os.environ.get("ADMIN_PASS", "")
    if not admin_pass:
        return False                     # auth disabled until a password is set
    return (hmac.compare_digest(username or "", admin_user)
            and hmac.compare_digest(password or "", admin_pass))


def issue_token(username: str) -> str:
    now = int(time.time())
    payload = {"sub": username, "iat": now, "exp": now + _ttl_min() * 60}
    return jwt.encode(payload, _secret(), algorithm="HS256")


def verify_token(token: str):
    try:
        return jwt.decode(token, _secret(), algorithms=["HS256"])
    except Exception:
        return None


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else request.args.get("token", "")
        claims = verify_token(token)
        if not claims:
            return jsonify({"error": "unauthorized"}), 401
        g.user = claims.get("sub")
        return fn(*args, **kwargs)
    return wrapper
