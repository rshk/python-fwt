from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.fernet import Fernet

from .serialization import TokenInfo, deserialize_token, serialize_token


class Authority:
    """
    Fernet Web Token authority
    """

    def __init__(self, key: bytes, token_type: str | None = None):
        self._fernet = Fernet(key)
        self._token_type = token_type

    def generate_key(self) -> bytes:
        return Fernet.generate_key()

    def encode(
        self,
        data: dict | bytes | str | None,
        valid_at: datetime | None = None,
        expires_at: datetime | None = None,
        expires_after: int | None = None,
        token_id: str | None = None,
    ) -> bytes:
        if (expires_at is None) and (expires_after is not None):
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_after)

        encoded = serialize_token(
            payload=data,
            valid_at=valid_at,
            expires_at=expires_at,
            token_type=self._token_type,
            token_id=token_id,
        )

        return self._fernet.encrypt(encoded)

    def decode(self, token: bytes) -> TokenInfo:
        encoded = self._fernet.decrypt(token)
        token_info = deserialize_token(encoded)

        now = datetime.now(timezone.utc)

        if token_info.valid_at is not None:
            if now < token_info.valid_at:
                raise ValueError("Token has not become valid yet")

        if token_info.expires_at is not None:
            if now >= token_info.expires_at:
                raise ValueError("Token has expired")

        if (token_info.token_type is not None) and (self._token_type is not None):
            if token_info.token_type != self._token_type:
                raise ValueError("Got a token of unexpected type")

        return token_info

    def decode_payload(self, token: bytes) -> Any:
        return self.decode(token).payload
