from unittest.mock import patch

import pytest
from freezegun import freeze_time

from fwt import Authority

DEFAULT_KEY = b"bg93rvEVr8OVrq7UDxgPQCBvovxSuIUjrbEBR5JwIAI="


def test_encode_and_decode_simple_payload():
    authority = Authority(DEFAULT_KEY)
    token = authority.encode({"user_id": "123"})
    data = authority.decode(token)
    assert data == {"user_id": "123"}


def test_matching_audience_is_accepted():
    authority = Authority(DEFAULT_KEY, aud="LOGIN")
    token = authority.encode({"user_id": "123"})
    data = authority.decode(token)
    assert data == {"user_id": "123"}


def test_mismatched_audience_raises_valueerror():
    bad_authority = Authority(DEFAULT_KEY, aud="something else")
    token = bad_authority.encode({"user_id": "123"})

    authority = Authority(DEFAULT_KEY, aud="LOGIN")

    with pytest.raises(ValueError):
        authority.decode(token)


def test_unexpired_token_is_accepted():
    authority = Authority(DEFAULT_KEY, aud="LOGIN")

    with freeze_time("2025-09-05 15:40:00"):
        token = authority.encode({}, expires_after=300)

    with freeze_time("2025-09-05 15:41:00"):
        assert authority.decode(token) == {}


def test_expired_token_raises_valueerror():
    authority = Authority(DEFAULT_KEY, aud="LOGIN")

    with freeze_time("2025-09-05 15:40:00"):
        token = authority.encode({}, expires_after=300)

    with freeze_time("2025-09-05 15:48:00"):
        with pytest.raises(ValueError):
            authority.decode(token)
