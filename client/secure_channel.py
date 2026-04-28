# client/secure_channel.py
import sys, os
import socket, json

# הוספת תיקיית השורש (DataSecured) ל-Path כדי למצוא את Encryption.py
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from cryptography.hazmat.primitives import serialization
from Encryption import (
    generate_aes_key, rsa_encrypt,
    encrypt_data, decrypt_data,
    enc_dict_to_bytes, enc_dict_from_bytes
)


# ---------- עזר לתקשורת (נשאר זהה לשרת) ----------
def recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def recv_frame(conn: socket.socket) -> bytes:
    hdr = recv_exact(conn, 4)
    ln = int.from_bytes(hdr, "big")
    return recv_exact(conn, ln)


def send_frame(conn: socket.socket, payload: bytes) -> None:
    conn.sendall(len(payload).to_bytes(4, "big") + payload)


# ---------- מחלקת ערוץ מאובטח (OOP) ----------
class SecureChannel:
    def __init__(self, host="127.0.0.1", port=6000):
        self.host = host
        self.port = port
        self.sock = None
        self.session_key = None  # זהו מפתח ה-Fernet

    def connect(self):
        """יוצר חיבור ראשוני ומבצע Handshake RSA להחלפת מפתח Fernet"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))

        # 1) קבלת מפתח ציבורי מהשרת
        send_frame(self.sock, b"GET_PUBLIC_KEY")
        pub_pem = recv_frame(self.sock)
        public_key = serialization.load_pem_public_key(pub_pem)

        # 2) יצירת מפתח Fernet ושליחתו מוצפן ב-RSA
        self.session_key = generate_aes_key()  # מייצר מפתח Fernet תקין
        enc_session_key = rsa_encrypt(public_key, self.session_key)
        send_frame(self.sock, enc_session_key)

        return self

    def request(self, payload: dict, expect_response=True):
        """שליחת בקשה מוצפנת וקבלת תשובה מוצפנת"""
        if not self.sock or not self.session_key:
            raise RuntimeError("Not connected to server")

        # הצפנה ב-Fernet (מחזיר Token)
        plaintext = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        token = encrypt_data(self.session_key, plaintext)

        # שליחה לשרת (הפיכת המחרוזת לבייטים)
        send_frame(self.sock, enc_dict_to_bytes(token))

        if not expect_response:
            return None

        # קבלת תשובה ופענוח Fernet
        enc_resp_bytes = recv_frame(self.sock)
        token_resp = enc_dict_from_bytes(enc_resp_bytes)
        pt_resp = decrypt_data(self.session_key, token_resp)

        return json.loads(pt_resp.decode("utf-8"))

    def close(self):
        try:
            self.request({"type": "logout"}, expect_response=False)
        except:
            pass
        if self.sock:
            self.sock.close()
            self.sock = None
            self.session_key = None