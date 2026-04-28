# server/socket_server.py
import sys, os
from pathlib import Path

# הוספת תיקיית השורש ל-Path כדי למצוא את Encryption.py
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import json, socket, threading
from datetime import datetime
from Encryption import (
    generate_rsa_private_key, public_key_pem, rsa_decrypt,
    encrypt_data, decrypt_data, enc_dict_to_bytes, enc_dict_from_bytes
)

# הגדרות קבועות
HOST = "0.0.0.0"
PORT = 6000
DB_PATH = Path(__file__).resolve().parent / "users_db.json"


# ---------- עזר לניהול בסיס נתונים ----------
def _load_db():
    if not DB_PATH.exists():
        return {}
    try:
        return json.loads(DB_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[WARN] Error loading DB: {e}")
        return {}


def _save_db(db):
    try:
        tmp = DB_PATH.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(db, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(DB_PATH)
    except Exception as e:
        print(f"[ERROR] Save DB failed: {e}")


# ---------- עזר לתקשורת (נשאר אותו דבר) ----------
def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk: raise ConnectionError("Closed")
        buf += chunk
    return buf


def recv_frame(conn):
    hdr = recv_exact(conn, 4)
    ln = int.from_bytes(hdr, "big")
    return recv_exact(conn, ln)


def send_frame(conn, payload):
    conn.sendall(len(payload).to_bytes(4, "big") + payload)


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")


# ---------- מחלקת השרת (OOP) ----------
class PasswordServer:
    def __init__(self, host=HOST, port=PORT):
        self.host = host
        self.port = port
        self.users = _load_db()
        self.private_key = generate_rsa_private_key()
        self.public_pem = public_key_pem(self.private_key.public_key())

    def start(self):
        log(f"Server starting on {self.host}:{self.port}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen(100)
            while True:
                conn, addr = s.accept()
                # דרישה 2+4: עבודה מקבילית עם תהליכונים
                threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()

    def handle_client(self, conn, addr):
        log(f"New connection from {addr}")
        try:
            # 1. RSA Handshake
            req = recv_frame(conn)
            if req != b"GET_PUBLIC_KEY": return
            send_frame(conn, self.public_pem)

            # 2. קבלת מפתח ה-Session (Fernet Key)
            enc_aes = recv_frame(conn)
            session_key = rsa_decrypt(self.private_key, enc_aes)
            log(f"Secure channel with {addr} established")

            while True:
                try:
                    enc_msg_bytes = recv_frame(conn)
                except (ConnectionError, ValueError):
                    break

                # פענוח Fernet (מחזיר בייטים של JSON)
                token = enc_dict_from_bytes(enc_msg_bytes)
                plaintext = decrypt_data(session_key, token)
                msg = json.loads(plaintext.decode("utf-8"))

                t = msg.get("type")
                resp = {"ok": False, "error": "unknown_action"}

                if t == "logout":
                    log(f"Logout: {addr}");
                    break

                elif t == "register":
                    user = (msg.get("username") or "").strip()
                    if user in self.users:
                        resp = {"ok": False, "error": "user_exists"}
                    else:
                        self.users[user] = {"salt": msg.get("salt"), "encrypted": msg.get("encrypted")}
                        _save_db(self.users)
                        resp = {"ok": True}
                        log(f"Registered user: {user}")

                elif t == "login":
                    user = (msg.get("username") or "").strip()
                    u = self.users.get(user)
                    if u:
                        resp = {"ok": True, "salt": u["salt"], "encrypted": u["encrypted"]}
                    else:
                        resp = {"ok": False, "error": "user_not_found"}

                elif t == "update_vault":
                    user = msg.get("username")
                    if user in self.users:
                        self.users[user]["encrypted"] = msg.get("encrypted")
                        _save_db(self.users)
                        resp = {"ok": True}
                        log(f"Vault updated for: {user}")

                # הצפנת התשובה ב-Fernet ושליחה
                token_resp = encrypt_data(session_key, json.dumps(resp).encode())
                send_frame(conn, enc_dict_to_bytes(token_resp))

        except Exception as e:
            log(f"Error handling {addr}: {e}")
        finally:
            conn.close()
            log(f"Disconnected: {addr}")


if __name__ == "__main__":
    server = PasswordServer()
    server.start()