"""3DS SDK stand-in for the app-channel test (independent of the Go code): jwcrypto (JWS/JWE) and pyca/cryptography
(ECDH), ConcatKDF written here from RFC 7518 §4.6.2 with the EMV 3DS parameters.
  sdk.py keygen STATE            -> prints the SDK ephemeral public JWK
  sdk.py creq STATE JWS ENC JSON -> verifies acsSignedContent, derives the key, prints the CReq JWE
  sdk.py cres STATE JWE          -> decrypts the CRes JWE, prints the plaintext"""
import base64, hashlib, json, struct, sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from jwcrypto import jwk, jws, jwe

def b64d(s): return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))
REF = 'DIFME-TEST-SDK-REF-1'

def concat_kdf(z):
    lp = lambda b: struct.pack('>I', len(b)) + b
    other = lp(b'') + lp(b'') + lp(REF.encode()) + struct.pack('>I', 256)
    return hashlib.sha256(b'\x00\x00\x00\x01' + z + other).digest()

def key_from(state, signed):
    st = json.load(open(state))
    hdr = json.loads(b64d(signed.split('.')[0]))
    cert = x509.load_der_x509_certificate(base64.b64decode(hdr['x5c'][0]))
    pub = jwk.JWK.from_pem(cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    s = jws.JWS(); s.deserialize(signed); s.verify(pub, alg='PS256')
    body = json.loads(s.payload)
    assert body['sdkEphemPubKey']['x'] == st['pub']['x'], 'ACS signed another SDK key'
    acs = jwk.JWK(**body['acsEphemPubKey']).get_op_key('verify')  # EC public key
    priv = serialization.load_pem_private_key(st['priv'].encode(), None)
    return concat_kdf(priv.exchange(ec.ECDH(), acs)), body['acsURL']

cmd = sys.argv[1]
if cmd == 'keygen':
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = json.loads(jwk.JWK.from_pyca(priv.public_key()).export_public())
    json.dump({'priv': priv.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(), 'pub': pub}, open(sys.argv[2], 'w'))
    print(json.dumps({'kty': 'EC', 'crv': 'P-256', 'x': pub['x'], 'y': pub['y']}))
elif cmd == 'creq':
    k, _ = key_from(sys.argv[2], sys.argv[3]); enc = sys.argv[4]; creq = sys.argv[5]
    kid = json.loads(creq)['acsTransID']
    cek = k if enc == 'A128CBC-HS256' else k[:16]
    e = jwe.JWE(creq.encode(), json.dumps({'alg': 'dir', 'enc': enc, 'kid': kid}))
    e.add_recipient(jwk.JWK(kty='oct', k=base64.urlsafe_b64encode(cek).decode().rstrip('=')))
    print(e.serialize(compact=True))
elif cmd == 'cres':
    st = json.load(open(sys.argv[2])); k = bytes.fromhex(st['k']); token = sys.argv[3]
    enc = json.loads(b64d(token.split('.')[0]))['enc']
    cek = k if enc == 'A128CBC-HS256' else k[16:]
    e = jwe.JWE(); e.deserialize(token, key=jwk.JWK(kty='oct', k=base64.urlsafe_b64encode(cek).decode().rstrip('=')))
    print(e.payload.decode())
elif cmd == 'savekey':
    k, _ = key_from(sys.argv[2], sys.argv[3]); st = json.load(open(sys.argv[2])); st['k'] = k.hex(); json.dump(st, open(sys.argv[2], 'w'))
