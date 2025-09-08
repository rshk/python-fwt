# Python Fernet Web Token

Library to produce and validate signed, encrypted tokens (via
[Fernet](https://cryptography.io/en/latest/fernet/)), to make them
suitable for carrying confidential state over an unprotected channel.

Intended as a replacement for the JWT series of protocols.

## Advantages compared to JWT

* Encryption support, allowing tokens to contain confidential data
  without exposing it to the user
* Tokens are encoded using a binary format, which is more concise than
  JSON
* Tokens do not carry (unverified) information about the encryption
  algorithm used, eliminating an entire class of vulnerabilities

## Supported features

* Validity start date: tokens will not be accepted before this date
* Expiration date: tokens will no longer be accepted after this date
* Token type, to distinguish between different classes of token issued using the same shared key
* Token payload can be binary data, a utf8 string, or JSON data, with support for user-extensible formats

## Usage example

``` python
import fwt

tf = fwt.Authority(key=b'...', token_type='Authentication')

# Create a token containing some JSON data
token = tf.encode({"user_id": 12345})

# Or binary data
token = tf.encode(b"\x00\x00\x00\x00\x00\x0009")

# Create a token with an expiration date
token = tf.encode({...}, expire_after=3600)
token = tf.encode({...}, expire_at=datetime(2030, 1, 1))

# Decode payload data from a token
data = tf.decode_payload(token)

# Or if extra information is needed
token_info = tf.decode(token)
token_info.payload  # the original data
token_info.token_id  # for example...
```

## Token binary format

Token data is encoded using a binary format. All numbers are stored in big-endian order.

The first byte contains a bitmask (four lower bits) to indicate the
presence of the optional fields (in order, lsb first), while the upper
four bits encode the payload type.

Following are a series of optional fields, as described below.

### Optional fields

* Validity start date: unix timestamp as an unsigned 64-bit integer
* Expiration date: unix timestamp as an unsigned 64-bit integer
* Token type: utf8 string, prefixed with a 8-bit integer indicating
  the encoded length
* Token ID: utf8 string, prefixed with a 8-bit integer indicating the
  encoded length
* Payload data: if the payload type is not 0, the payload is encoded
  as a 2-byte number indicating the encoded size, followed by that
  amount of bytes

### Payload types

* 0: empty
* 1: binary data
* 2: utf8 encoded string
* 3: JSON encoded data
* 4-7: reserved
* 8-15: application specific usage
