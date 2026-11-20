from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import re
from collections.abc import Sequence


_MAX_TOKEN_LENGTH = 8192


class CursorError(ValueError):
    pass


@dataclass(frozen=True)
class Cursor:
    scope: str
    after: tuple[str | int | float | bool | None, ...]
    snapshot: str | int | None
    issued_at: int
    expires_at: int


class CursorCodec:
    def __init__(self, secret: bytes):
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("secret must contain at least 32 bytes")
        self._secret = secret

    def encode(
        self,
        *,
        scope: str,
        after: Sequence[str | int | float | bool | None],
        now: int,
        ttl_seconds: int,
        snapshot: str | int | None = None,
    ) -> str:
        if (
            not isinstance(scope, str)
            or not scope
            or not after
            or (snapshot is not None and not isinstance(snapshot, str) and type(snapshot) is not int)
            or type(now) is not int
            or type(ttl_seconds) is not int
            or ttl_seconds < 1
        ):
            raise ValueError("scope, a non-empty position, integer time, and positive integer TTL are required")
        self._validate_position(after)
        payload = {
            "v": 1,
            "scope": scope,
            "after": list(after),
            "snapshot": snapshot,
            "iat": now,
            "exp": now + ttl_seconds,
        }
        raw = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        body = self._b64encode(raw)
        signature = self._b64encode(
            hmac.new(self._secret, body.encode("ascii"), hashlib.sha256).digest()
        )
        token = body + "." + signature
        if len(token) > _MAX_TOKEN_LENGTH:
            raise ValueError("cursor is too large")
        return token

    def decode(self, token: str, *, scope: str, now: int) -> Cursor:
        if not isinstance(token, str) or type(now) is not int:
            raise CursorError("cursor and integer current time are required")
        if len(token) > _MAX_TOKEN_LENGTH:
            raise CursorError("cursor is too large")
        parts = token.split(".")
        if len(parts) != 2 or any(not re.fullmatch(r"[A-Za-z0-9_-]+", part) for part in parts):
            raise CursorError("malformed cursor")
        body, supplied_signature = parts
        expected = self._b64encode(
            hmac.new(self._secret, body.encode("ascii"), hashlib.sha256).digest()
        )
        if not hmac.compare_digest(supplied_signature, expected):
            raise CursorError("cursor signature is invalid")

        try:
            payload = json.loads(self._b64decode(body))
        except (binascii.Error, ValueError, UnicodeDecodeError) as error:
            raise CursorError("cursor payload is invalid") from error
        if not isinstance(payload, dict) or payload.get("v") != 1:
            raise CursorError("unsupported cursor version")
        if payload.get("scope") != scope:
            raise CursorError("cursor does not match this query")

        issued_at = payload.get("iat")
        expires_at = payload.get("exp")
        if type(issued_at) is not int or type(expires_at) is not int:
            raise CursorError("cursor timestamps are invalid")
        if issued_at > now or expires_at <= now or expires_at <= issued_at:
            raise CursorError("cursor has expired or was issued in the future")

        after = payload.get("after")
        if not isinstance(after, list) or not after:
            raise CursorError("cursor position is invalid")
        try:
            self._validate_position(after)
        except ValueError as error:
            raise CursorError(str(error)) from error
        snapshot = payload.get("snapshot")
        if snapshot is not None and not isinstance(snapshot, str) and type(snapshot) is not int:
            raise CursorError("cursor snapshot must be a string or integer")
        return Cursor(scope, tuple(after), snapshot, issued_at, expires_at)

    @staticmethod
    def _validate_position(values: Sequence[object]) -> None:
        for value in values:
            if value is not None and type(value) not in (str, int, float, bool):
                raise ValueError("cursor positions must contain JSON scalar values")
            if isinstance(value, float) and not math.isfinite(value):
                raise ValueError("cursor positions cannot contain NaN or infinity")

    @staticmethod
    def _b64encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

    @staticmethod
    def _b64decode(value: str) -> bytes:
        padded = value + "=" * (-len(value) % 4)
        return base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
