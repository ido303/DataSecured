# Encryption.py
import os, base64, json
from typing import Dict, Any, Union

# ===== KDF (לכספת) =====
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=390_000, backend=default_backend()
    )
    return kdf.derive(password.encode("utf-8"))

# ===== AES-GCM =====
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_data(key: bytes, plaintext: bytes) -> Dict[str, str]:
    nonce = os.urandom(12)
    enc = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend()).encryptor()
    ciphertext = enc.update(plaintext) + enc.finalize()
    return {
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
        "tag": base64.b64encode(enc.tag).decode("utf-8"),
    }

def decrypt_data(key: bytes, enc_dict: Dict[str, str]) -> bytes:
    nonce = base64.b64decode(enc_dict["nonce"])
    ciphertext = base64.b64decode(enc_dict["ciphertext"])
    tag = base64.b64decode(enc_dict["tag"])
    dec = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend()).decryptor()
    return dec.update(ciphertext) + dec.finalize()

# ===== RSA (Handshake) =====
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

def generate_rsa_private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def public_key_pem(pub) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def rsa_encrypt(public_key, data: bytes) -> bytes:
    return public_key.encrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )

def rsa_decrypt(private_key, data: bytes) -> bytes:
    return private_key.decrypt(
        data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )

def generate_aes_key(nbytes: int = 32) -> bytes:
    return os.urandom(nbytes)

# ===== עזר ל-wire =====
def enc_dict_to_bytes(d: Dict[str,str]) -> bytes:
    return json.dumps(d, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def enc_dict_from_bytes(b: Union[bytes, bytearray]) -> Dict[str,str]:
    return json.loads(b.decode("utf-8"))

# ===== Aliases לקוד ישן =====
def aes_encrypt(key: bytes, plaintext: bytes) -> Dict[str, str]:
    return encrypt_data(key, plaintext)

def aes_decrypt(key: bytes, enc: Union[Dict[str, str], str, bytes, bytearray]) -> bytes:
    if isinstance(enc, (bytes, bytearray)):
        enc = json.loads(enc.decode("utf-8"))
    elif isinstance(enc, str):
        enc = json.loads(enc)
    return decrypt_data(key, enc)
