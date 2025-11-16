# scripts/gen_ca.py
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import os

# Where to save keys/certs
CERTS_DIR = "certs"
os.makedirs(CERTS_DIR, exist_ok=True)

# Generate RSA private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Write private key to file (PEM, no password)
with open(f"{CERTS_DIR}/root_ca_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Build self-signed certificate
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Karachi"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat CA"),
    x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat Root CA"),
])

cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
    private_key.public_key()
).serial_number(
    x509.random_serial_number()
).not_valid_before(
    datetime.utcnow()
).not_valid_after(
    datetime.utcnow() + timedelta(days=3650)  # 10 years
).add_extension(
    x509.BasicConstraints(ca=True, path_length=None), critical=True,
).sign(private_key, hashes.SHA256())

# Write certificate to file
with open(f"{CERTS_DIR}/root_ca_cert.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print("[+] Root CA generated successfully:")
print(f" - Private key: {CERTS_DIR}/root_ca_key.pem")
print(f" - Certificate: {CERTS_DIR}/root_ca_cert.pem")

