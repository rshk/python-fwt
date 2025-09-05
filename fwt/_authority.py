import json
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.fernet import Fernet


class Authority:
    """
    Fernet Web Token authority
    """

    def __init__(self, key: bytes, aud: str | None = None):
        self._fernet = Fernet(key)
        self._audience = aud

    def generate_key(self) -> bytes:
        return Fernet.generate_key()

    def encode(
        self,
        data: dict,
        expires_at: datetime | None = None,
        expires_after: int | None = None,
    ) -> bytes:
        payload: dict[str, Any] = {"data": data}

        if self._audience is not None:
            payload["aud"] = self._audience

        if expires_at is None and expires_after is not None:
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_after)

        if expires_at is not None:
            payload["exp"] = expires_at.timestamp()

        enc_payload = json.dumps(payload).encode()
        return self._fernet.encrypt(enc_payload)

    def decode(self, token: bytes) -> dict:
        enc_payload = self._fernet.decrypt(token)
        payload = json.loads(enc_payload.decode())

        if "aud" in payload:
            if payload["aud"] != self._audience:
                raise ValueError("Mismatched token audience")

        if "exp" in payload:
            expires_at = datetime.fromtimestamp(payload["exp"], timezone.utc)
            now = datetime.now(timezone.utc)
            if now >= expires_at:
                raise ValueError("Token is expired")

        return payload["data"]
