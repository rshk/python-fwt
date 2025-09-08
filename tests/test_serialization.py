from datetime import datetime, timezone
from io import BytesIO

import pytest

from fwt.serialization import (
    PT_BINARY,
    PT_EMPTY,
    PT_JSON,
    PT_STRING,
    PackedDataStreamWrapper,
    TokenInfo,
    decode_payload,
    deserialize_token,
    encode_payload,
    serialize_token,
)


def test_roundtrip_empty_token():
    token = serialize_token(None)

    token_info = deserialize_token(token)
    assert isinstance(token_info, TokenInfo)
    assert token_info.valid_at is None
    assert token_info.expires_at is None
    assert token_info.token_type is None
    assert token_info.token_id is None
    assert token_info.payload_type == PT_EMPTY
    assert token_info.payload is None


class Test_PackedDataStreamWrapper:
    @pytest.mark.parametrize(
        "value,expected", [(1, b"\x01"), (100, b"\x64"), (255, b"\xff")]
    )
    def test_pack_u8(self, value, expected):
        stream = BytesIO()
        pdsw = PackedDataStreamWrapper(stream)
        pdsw.write_u8(value)
        assert stream.getvalue() == expected

    @pytest.mark.parametrize("value", [1, 100, 255])
    def test_roundtrip_u8(self, value):
        stream = BytesIO()
        pdsw = PackedDataStreamWrapper(stream)
        pdsw.write_u8(value)

        # Create a brand new stream
        reader = PackedDataStreamWrapper(BytesIO(stream.getvalue()))
        assert reader.read_u8() == value

    @pytest.mark.parametrize(
        "value",
        [
            datetime(1970, 1, 1, 0, 0, tzinfo=timezone.utc),
            datetime(2025, 9, 10, 0, 0, tzinfo=timezone.utc),
            datetime(2040, 12, 31, 12, 30, tzinfo=timezone.utc),
        ],
        ids=str,
    )
    def test_roundtrip_timestamp(self, value):
        stream = BytesIO()
        pdsw = PackedDataStreamWrapper(stream)
        pdsw.write_timestamp(value)

        # Create a brand new stream
        reader = PackedDataStreamWrapper(BytesIO(stream.getvalue()))
        assert reader.read_timestamp() == value
