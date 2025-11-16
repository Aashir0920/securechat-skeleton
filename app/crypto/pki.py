from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from pathlib import Path

# Path relative to the project root
CERT_DIR = Path(__file__).resolve().parent.parent.parent / "certs"

def load_certificate(cert_file: str): 
    path = CERT_DIR / cert_file 
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())

def load_certificate_bytes(cert_bytes):
    """Load certificate from bytes"""
    return x509.load_pem_x509_certificate(cert_bytes, default_backend())

def load_private_key(filepath, password=None):
    """Load private key from PEM file"""
    path = CERT_DIR / filepath 
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(), 
            password=password, 
            backend=default_backend()
        )
