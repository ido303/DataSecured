import os, base64, json
from typing import Dict, Any, Union
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# ===== KDF (לכספת ולמפתחות) =====
def derive_key(password: str, salt: bytes) -> bytes:
    """מייצר מפתח תקין ל-Fernet מסיסמה ו-Salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390_000,
        backend=default_backend()
    )
    # Fernet דורשת מפתח בפורמט URL-safe base64
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

# ===== Fernet Encryption =====
def encrypt_data(key: bytes, plaintext: bytes) -> str:
    """הצפנת מידע והחזרת מחרוזת (Token)"""
    f = Fernet(key)
    return f.encrypt(plaintext).decode("utf-8")

def decrypt_data(key: bytes, token: Union[str, bytes]) -> bytes:
    """פענוח הטוקן וחזרה לבייטים"""
    if isinstance(token, str):
        token = token.encode("utf-8")
    f = Fernet(key)
    return f.decrypt(token)

# ===== RSA (Handshake - ללא שינוי) =====
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
    """מייצר מפתח רנדומלי בפורמט שמתאים ל-Fernet"""
    return Fernet.generate_key()

# ===== פונקציות עזר (מותאמות ל-Fernet) =====
def enc_dict_to_bytes(token: str) -> bytes:
    """הופך את הטוקן של פרנט לבייטים למשלוח"""
    return token.encode("utf-8")

def enc_dict_from_bytes(b: bytes) -> str:
    """הופך בייטים מהרשת חזרה לטוקן"""
    return b.decode("utf-8")