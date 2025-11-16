from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# RFC 3526 2048-bit MODP Group parameters
P = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'
        '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'
        'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'
        'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
        'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D'
        'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'
        '83655D23DCA3AD961C62F356208552BB9ED529077096966D'
        '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
        'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9'
        'DE2BCBF6955817183995497CEA956AE515D2261898FA0510'
        '15728E5A8AACAA68FFFFFFFFFFFFFFFF', 16)
G = 2

def generate_private_key():
    """Generate DH private key"""
    params = dh.DHParameterNumbers(P, G).parameters(default_backend())
    return params.generate_private_key()

def serialize_public_key(public_key):
    """Serialize DH public key to bytes"""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_public_key(public_key_bytes):
    """Deserialize DH public key from bytes"""
    return serialization.load_pem_public_key(public_key_bytes, default_backend())
