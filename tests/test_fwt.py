from datetime import datetime, timezone

import pytest
from freezegun import freeze_time

from fwt import Authority
from fwt.serialization import PT_BINARY, PT_EMPTY, PT_JSON, PT_STRING

DEFAULT_KEY = b"bg93rvEVr8OVrq7UDxgPQCBvovxSuIUjrbEBR5JwIAI="


@pytest.fixture()
def authority():
    return Authority(DEFAULT_KEY)


def test_encode_empty_payload():
    authority = Authority(DEFAULT_KEY)
    token = authority.encode(None)
    assert authority._fernet.decrypt(token) == b"\x00"


def test_roundtrip_empty_payload():
    authority = Authority(DEFAULT_KEY)
    token = authority.encode(None)
    token_info = authority.decode(token)
    assert token_info.payload_type == PT_EMPTY
    assert token_info.payload is None


@pytest.mark.parametrize("value", [b"", b"HELLO", "🍕".encode()])
def test_roundtrip_binary_payload(value):
    authority = Authority(DEFAULT_KEY)
    token = authority.encode(value)
    token_info = authority.decode(token)
    assert token_info.payload_type == PT_BINARY
    assert isinstance(token_info.payload, bytes)
    assert token_info.payload == value


@pytest.mark.parametrize("value", ["", "HELLO", "🍕"])
def test_roundtrip_string_payload(value):
    authority = Authority(DEFAULT_KEY)
    token = authority.encode(value)
    token_info = authority.decode(token)
    assert token_info.payload_type == PT_STRING
    assert isinstance(token_info.payload, str)
    assert token_info.payload == value


@pytest.mark.parametrize(
    "value",
    [{}, [], {"user_id": "hello-world"}, {"items": [1, 2, 3]}, ["foo", "bar"]],
)
def test_roundtrip_json_payload(value):
    authority = Authority(DEFAULT_KEY)
    token = authority.encode(value)
    token_info = authority.decode(token)
    assert token_info.payload_type == PT_JSON
    assert token_info.payload == value


class Test_valid_at:
    @pytest.fixture()
    def token(self, authority: Authority):
        return authority.encode({}, valid_at=datetime(2025, 9, 1, tzinfo=timezone.utc))

    def test_token_is_accepted_after_validity_start(self, authority, token):
        with freeze_time("2025-09-10 12:30:00"):
            assert authority.decode_payload(token) == {}

    def test_token_is_accepted_at_validity_start(self, authority, token):
        with freeze_time("2025-09-01 00:00:00"):
            assert authority.decode_payload(token) == {}

    def test_token_is_rejected_before_validity_start(self, authority, token):
        with freeze_time("2025-08-31 23:59:59"):
            with pytest.raises(ValueError):
                authority.decode_payload(token)


class Test_expires_at:
    @pytest.fixture()
    def token(self, authority: Authority):
        return authority.encode(
            {}, expires_at=datetime(2025, 9, 1, tzinfo=timezone.utc)
        )

    def test_token_is_accepted_before_expiration_date(self, authority, token):
        with freeze_time("2025-01-01 00:00:00"):
            assert authority.decode_payload(token) == {}

        with freeze_time("2025-08-31 23:59:59"):
            assert authority.decode_payload(token) == {}

    def test_token_is_rejected_at_expiration_date(self, authority, token):
        with freeze_time("2025-09-01 00:00:00"):
            with pytest.raises(ValueError):
                authority.decode_payload(token)

    def test_token_is_rejected_after_expiration_date(self, authority, token):
        with freeze_time("2025-10-31 23:59:59"):
            with pytest.raises(ValueError):
                authority.decode_payload(token)


class Test_token_type:
    def test_token_with_matching_type_is_accepted(self):
        authority = Authority(DEFAULT_KEY, token_type="LOGIN")
        token = Authority(DEFAULT_KEY, token_type="LOGIN").encode({"user_id": 1234})
        authority = Authority(DEFAULT_KEY, token_type="LOGIN")
        assert authority.decode_payload(token) == {"user_id": 1234}

    def test_token_with_mismatching_type_is_rejected(self):
        token = Authority(DEFAULT_KEY, token_type="FUBAR").encode({"user_id": 1234})
        authority = Authority(DEFAULT_KEY, token_type="LOGIN")
        with pytest.raises(ValueError):
            authority.decode_payload(token)


class Test_token_id:
    @pytest.mark.parametrize("value", ["abcd-1234", "🍕"])
    def test_token_id_can_be_retrieved(self, authority, value):
        token = authority.encode(b"X", token_id=value)
        token_info = authority.decode(token)
        assert token_info.token_id == value
