# client/secure_channel.py
import sys, os
# הוסף את תיקיית השורש (DataSecured) ל-PYTHONPATH כדי ש-Encryption יימצא
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import socket, json
from cryptography.hazmat.primitives import serialization
from Encryption import (
    generate_aes_key, rsa_encrypt,
    encrypt_data, decrypt_data,
    enc_dict_to_bytes, enc_dict_from_bytes
)

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

class SecureChannel:
    def __init__(self, host="127.0.0.1", port=6000):
        self.host = host
        self.port = port
        self.sock = None
        self.aes_key = None

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))

        # 1) GET_PUBLIC_KEY
        send_frame(self.sock, b"GET_PUBLIC_KEY")
        pub_pem = recv_frame(self.sock)
        public_key = serialization.load_pem_public_key(pub_pem)

        # 2) AES session
        self.aes_key = generate_aes_key()
        enc_aes = rsa_encrypt(public_key, self.aes_key)
        send_frame(self.sock, enc_aes)
        return self

    def request(self, payload: dict, expect_response=True):
        if not self.sock or not self.aes_key:
            raise RuntimeError("not connected")
        # encrypt
        pt = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        enc = encrypt_data(self.aes_key, pt)
        send_frame(self.sock, enc_dict_to_bytes(enc))
        if not expect_response:
            return None
        enc_resp_bytes = recv_frame(self.sock)
        enc_resp = enc_dict_from_bytes(enc_resp_bytes)
        pt_resp = decrypt_data(self.aes_key, enc_resp)
        return json.loads(pt_resp.decode("utf-8"))

    def close(self):
        try:
            self.request({"type": "logout"}, expect_response=False)
        except Exception:
            pass
        if self.sock:
            self.sock.close()
            self.sock = None
            self.aes_key = None
