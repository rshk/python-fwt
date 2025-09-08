import json
from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO
from typing import Any

PT_EMPTY = 0
PT_BINARY = 1
PT_STRING = 2
PT_JSON = 3

FL_VALID_AT = 1 << 0
FL_EXPIRES_AT = 1 << 1
FL_TOKEN_TYPE = 1 << 2
FL_TOKEN_ID = 1 << 3

_JSON_TYPES = (dict, list, tuple, int, float)


@dataclass
class TokenInfo:
    valid_at: datetime | None = None
    expires_at: datetime | None = None
    token_type: str | None = None
    token_id: str | None = None
    payload_type: int | None = PT_EMPTY
    payload: Any | None = None


def serialize_token(
    payload: Any,
    payload_type: int | None = None,
    valid_at: datetime | None = None,
    expires_at: datetime | None = None,
    token_type: str | None = None,
    token_id: str | None = None,
) -> bytes:
    if payload_type is None:
        payload_type = guess_payload_type(payload)

    enc_payload = encode_payload(payload, payload_type)

    flag = 0
    stream = BytesIO()
    stream.write(b"\x00")  # Empty flag for now
    pdsw = PackedDataStreamWrapper(stream)

    if valid_at is not None:
        flag |= FL_VALID_AT
        pdsw.write_timestamp(valid_at)

    if expires_at is not None:
        flag |= FL_EXPIRES_AT
        pdsw.write_timestamp(expires_at)

    if token_type is not None:
        flag |= FL_TOKEN_TYPE
        pdsw.write_string8(token_type)

    if token_id is not None:
        flag |= FL_TOKEN_ID
        pdsw.write_string8(token_id)

    flag |= payload_type << 4

    if payload_type != PT_EMPTY:
        assert enc_payload is not None
        pdsw.write_bytes16(enc_payload)

    # Go back and update the flags byte
    stream.seek(0)
    pdsw.write_u8(flag)

    return stream.getvalue()


def deserialize_token(data: bytes) -> TokenInfo:
    stream = BytesIO(data)
    pdsw = PackedDataStreamWrapper(stream)

    token_info = TokenInfo()
    flag = pdsw.read_u8()

    if flag & FL_VALID_AT:
        token_info.valid_at = pdsw.read_timestamp()

    if flag & FL_EXPIRES_AT:
        token_info.expires_at = pdsw.read_timestamp()

    if flag & FL_TOKEN_TYPE:
        token_info.token_type = pdsw.read_string8()

    if flag & FL_TOKEN_ID:
        token_info.token_id = pdsw.read_string8()

    payload_type = (flag >> 4) & 0b1111
    token_info.payload_type = payload_type
    enc_payload = pdsw.read_bytes16()
    token_info.payload = decode_payload(enc_payload, payload_type)

    return token_info


def encode_payload(payload: Any, payload_type: int) -> bytes | None:
    if not (0 <= payload_type < 8):
        raise ValueError("Payload type must be in range 0-7")

    if payload_type == PT_EMPTY:
        # Silently ignore a payload
        return None

    if payload_type == PT_BINARY:
        if not isinstance(payload, bytes):
            raise TypeError("Payload must be bytes")
        return payload

    if payload_type == PT_STRING:
        if not isinstance(payload, str):
            raise TypeError("Payload must be a string")
        return payload.encode()

    if payload_type == PT_JSON:
        if not isinstance(payload, _JSON_TYPES):
            raise TypeError("Payload must be a JSON-compatible type")
        return json.dumps(payload).encode()

    if not isinstance(payload, bytes):
        raise TypeError("Custom-encoded payload must be bytes")

    return payload


def guess_payload_type(payload: Any) -> int:
    if payload is None:
        return PT_EMPTY

    if isinstance(payload, bytes):
        return PT_BINARY

    if isinstance(payload, str):
        return PT_STRING

    if isinstance(payload, _JSON_TYPES):
        return PT_JSON

    raise ValueError(f"Unable to guess payload type for {type(payload)}")


def decode_payload(data: bytes, payload_type: int) -> Any:
    if payload_type == PT_EMPTY:
        return None

    if payload_type == PT_BINARY:
        return data

    if payload_type == PT_STRING:
        return data.decode()

    if payload_type == PT_JSON:
        return json.loads(data.decode())

    return data


class PackedDataStreamWrapper:
    def __init__(self, stream: BytesIO):
        self._stream = stream

    def read_u8(self) -> int:
        return int.from_bytes(self._stream.read(1))

    def write_u8(self, value: int):
        self._stream.write(value.to_bytes(1))

    def read_u16(self) -> int:
        return int.from_bytes(self._stream.read(2))

    def write_u16(self, value: int):
        self._stream.write(value.to_bytes(2))

    def read_u64(self) -> int:
        return int.from_bytes(self._stream.read(8), signed=False)

    def write_u64(self, value: int):
        self._stream.write(value.to_bytes(8, signed=False))

    def read_string8(self) -> str:
        length = self.read_u8()
        enc = self._stream.read(length)
        return enc.decode()

    def write_string8(self, value: str):
        enc = value.encode()
        self.write_u8(len(enc))
        self._stream.write(enc)

    def read_bytes16(self) -> bytes:
        length = self.read_u16()
        enc = self._stream.read(length)
        return enc

    def write_bytes16(self, value: bytes):
        self.write_u16(len(value))
        self._stream.write(value)

    def read_timestamp(self) -> datetime:
        raw = self.read_u64()
        return datetime.fromtimestamp(raw, timezone.utc)

    def write_timestamp(self, value: datetime):
        ts = int(value.timestamp())
        self.write_u64(ts)
