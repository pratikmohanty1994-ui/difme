"""Hyperswitch stand-in (jwcrypto, independent of the Go code): encrypts card data as Hyperswitch's encrypt_jwe does
(RSA-OAEP-256 + A128GCM, kid) and decrypts the token service's JWE response with Hyperswitch's private key.
  hyperswitch.py encrypt ADAPTER_PUB_PEM JSON   -> JWE compact
  hyperswitch.py decrypt HS_PRIV_PEM JWE        -> plaintext"""
import sys, json
from jwcrypto import jwk, jwe
cmd, keyfile, data = sys.argv[1], sys.argv[2], sys.argv[3]
key = jwk.JWK.from_pem(open(keyfile, 'rb').read())
if cmd == 'encrypt':
    e = jwe.JWE(data.encode(), json.dumps({'alg': 'RSA-OAEP-256', 'enc': 'A128GCM', 'kid': 'hs-key-1'}))
    e.add_recipient(key); print(e.serialize(compact=True))
else:
    e = jwe.JWE(); e.deserialize(data, key=key); print(e.payload.decode())
