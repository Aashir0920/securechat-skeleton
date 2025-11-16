from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

def encrypt_message(key, plaintext):
    """Encrypt message with AES-128-CBC"""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode()
    
    # Generate random IV
    iv = os.urandom(16)
    
    # Pad plaintext to block size
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)
    
    # Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    
    return iv + ciphertext

def decrypt_message(key, ciphertext):
    """Decrypt message with AES-128-CBC"""
    # Extract IV and ciphertext
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    
    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    
    # Remove padding
    pad_len = padded[-1]
    return padded[:-pad_len]
