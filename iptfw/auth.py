from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
from pathlib import Path

from fastapi import HTTPException, Request
from fastapi.responses import RedirectResponse


COOKIE_NAME = "iptfw_session"
SESSION_TTL_SECONDS = 8 * 60 * 60


class Auth:
    def __init__(self, secret_path: Path, admin_password: str | None, dev_mode: bool) -> None:
        if not admin_password and not dev_mode:
            raise RuntimeError("IPTFW_ADMIN_PASSWORD must be set unless IPTFW_DEV_MODE=1")
        self.admin_password = admin_password or "admin"
        self.secret = self._load_secret(secret_path)

    def verify_password(self, password: str) -> bool:
        return hmac.compare_digest(password, self.admin_password)

    def issue_cookie(self, actor: str = "admin") -> str:
        expires = int(time.time()) + SESSION_TTL_SECONDS
        payload = f"{actor}:{expires}"
        sig = hmac.new(self.secret, payload.encode(), hashlib.sha256).hexdigest()
        return base64.urlsafe_b64encode(f"{payload}:{sig}".encode()).decode()

    def actor(self, request: Request) -> str | None:
        raw = request.cookies.get(COOKIE_NAME)
        if not raw:
            return None
        try:
            decoded = base64.urlsafe_b64decode(raw.encode()).decode()
            actor, expires_raw, sig = decoded.rsplit(":", 2)
            payload = f"{actor}:{expires_raw}"
            expected = hmac.new(self.secret, payload.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expected):
                return None
            if int(expires_raw) < int(time.time()):
                return None
            return actor
        except Exception:
            return None

    def require(self, request: Request) -> str:
        actor = self.actor(request)
        if not actor:
            raise HTTPException(status_code=303, headers={"Location": "/login"})
        return actor

    @staticmethod
    def redirect_with_cookie(url: str, cookie: str) -> RedirectResponse:
        response = RedirectResponse(url, status_code=303)
        response.set_cookie(COOKIE_NAME, cookie, httponly=True, samesite="strict")
        return response

    @staticmethod
    def logout_response() -> RedirectResponse:
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(COOKIE_NAME)
        return response

    def _load_secret(self, path: Path) -> bytes:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            return path.read_bytes()
        secret = secrets.token_bytes(32)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(secret)
        return secret
