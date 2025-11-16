# scripts/gen_cert.py
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import os
import sys

CERTS_DIR = "certs"
os.makedirs(CERTS_DIR, exist_ok=True)

# Usage: python gen_cert.py server OR python gen_cert.py client
if len(sys.argv) != 2:
    print("Usage: python gen_cert.py [server|client]")
    sys.exit(1)

entity = sys.argv[1]

# Load Root CA key and cert
with open(f"{CERTS_DIR}/root_ca_key.pem", "rb") as f:
    ca_key = serialization.load_pem_private_key(f.read(), password=None)

with open(f"{CERTS_DIR}/root_ca_cert.pem", "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read())

# Generate entity key
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Save private key
key_file = f"{CERTS_DIR}/{entity}_key.pem"
with open(key_file, "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Build certificate
subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
    x509.NameAttribute(NameOID.COMMON_NAME, f"{entity}.securechat.local"),
])

cert = x509.CertificateBuilder().subject_name(
    subject
).issuer_name(
    ca_cert.subject
).public_key(
    key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.utcnow()
).not_valid_after(
    datetime.utcnow() + timedelta(days=365)
).add_extension(
    x509.SubjectAlternativeName([x509.DNSName(f"{entity}.securechat.local")]),
    critical=False
).sign(ca_key, hashes.SHA256())

# Save certificate
cert_file = f"{CERTS_DIR}/{entity}_cert.pem"
with open(cert_file, "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print(f"[+] {entity.capitalize()} certificate issued successfully:")
print(f" - Private key: {key_file}")
print(f" - Certificate: {cert_file}")

