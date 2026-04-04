import hashlib
import hmac
import secrets
from functools import wraps
from typing import Iterable, Optional

from flask import current_app, g, jsonify, request

from utils import to_epoch, to_iso


PBKDF2_ALGORITHM = "sha256"
PBKDF2_ITERATIONS = 390000
ROLE_LEVELS = {
    "viewer": 1,
    "analyst": 2,
    "admin": 3,
}


def hash_password(password: str) -> str:
    if not password:
        raise ValueError("password is required")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        PBKDF2_ALGORITHM,
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
    )
    return "{0}${1}${2}${3}".format(
        PBKDF2_ALGORITHM,
        PBKDF2_ITERATIONS,
        salt.hex(),
        digest.hex(),
    )


def verify_password(password: str, stored_hash: str) -> bool:
    if not password or not stored_hash:
        return False

    try:
        algorithm, iterations_raw, salt_hex, digest_hex = stored_hash.split("$", 3)
        iterations = int(iterations_raw)
        salt = bytes.fromhex(salt_hex)
        expected_digest = bytes.fromhex(digest_hex)
    except (TypeError, ValueError):
        return False

    candidate_digest = hashlib.pbkdf2_hmac(
        algorithm,
        password.encode("utf-8"),
        salt,
        iterations,
    )
    return hmac.compare_digest(candidate_digest, expected_digest)


def issue_auth_token() -> str:
    return secrets.token_urlsafe(36)


def role_allows(user_role: str, required_roles: Iterable[str]) -> bool:
    user_level = ROLE_LEVELS.get((user_role or "").strip().lower(), 0)
    return any(user_level >= ROLE_LEVELS.get((role or "").strip().lower(), 0) for role in required_roles)


def extract_bearer_token(auth_header: str) -> str:
    raw_value = (auth_header or "").strip()
    if not raw_value:
        return ""
    parts = raw_value.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return ""
    return parts[1].strip()


def get_current_auth_session(touch: bool = True) -> Optional[dict]:
    cached = getattr(g, "_auth_session", None)
    if cached is not None:
        return cached

    token = extract_bearer_token(request.headers.get("Authorization", ""))
    if not token:
        token = (request.cookies.get("waf_session") or "").strip()
    if not token:
        g._auth_session = None
        return None

    storage = current_app.config["STORAGE"]
    session = storage.get_auth_session(token)
    if session is None:
        g._auth_session = None
        return None

    if touch:
        settings = current_app.config["APP_SETTINGS"]
        session = storage.touch_auth_session(token, settings.auth_token_ttl_seconds) or session

    g._auth_session = session
    g.current_user = session.get("user")
    g.current_token = token
    return session


def require_auth(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        session = get_current_auth_session()
        if session is None:
            return jsonify({"message": "Authentication required"}), 401
        return view_func(*args, **kwargs)

    return wrapper


def require_roles(*roles: str):
    def decorator(view_func):
        @wraps(view_func)
        @require_auth
        def wrapper(*args, **kwargs):
            session = get_current_auth_session(touch=False) or {}
            user = session.get("user") or {}
            if not role_allows(user.get("role", ""), roles):
                return (
                    jsonify(
                        {
                            "message": "You do not have permission to perform this action",
                            "required_roles": list(roles),
                            "role": user.get("role"),
                        }
                    ),
                    403,
                )
            return view_func(*args, **kwargs)

        return wrapper

    return decorator


def audit_details_from_request() -> dict:
    return {
        "ip_address": request.headers.get("X-Forwarded-For") or request.remote_addr or "",
        "user_agent": request.headers.get("User-Agent", ""),
        "path": request.path,
        "method": request.method,
        "recorded_at": to_iso(),
        "recorded_at_epoch": to_epoch(),
    }
