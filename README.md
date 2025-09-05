# Python Fernet Web Token

Produce signed, encrypted tokens using [Fernet](https://cryptography.io/en/latest/fernet/) encryption.

# Usage

``` python
import fwt

tf = fwt.Authority(key=b'...', aud='AUTH')

token = tf.encode({...}, expire_after=3600)
token = tf.encode({...}, expire_at=datetime(2030, 1, 1))
data = tf.decode(token)
```
