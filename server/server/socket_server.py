# server/socket_server.py
import sys, os
sys.path.append(os.path.dirname(os.path.dirname(__file__)))  # גישה ל-Encryption.py בשורש

import json, socket, threading
from typing import Dict, Any
from pathlib import Path
from datetime import datetime

from Encryption import (
    generate_rsa_private_key, public_key_pem, rsa_decrypt,
    encrypt_data, decrypt_data, enc_dict_to_bytes, enc_dict_from_bytes
)

# הגדרות שרת
HOST = "0.0.0.0"
PORT = 6000
DB_PATH = Path(__file__).resolve().parent / "users_db.json"

# ---------- ניהול בסיס נתונים ----------
def _load_db() -> Dict[str, Any]:
    """טוען את users_db.json לקובץ זיכרון"""
    if not DB_PATH.exists():
        return {}
    try:
        return json.loads(DB_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        print("[WARN] load DB:", e)
        return {}

def _save_db(db: Dict[str, Any]) -> None:
    """שומר את מסד הנתונים לקובץ (עם קובץ זמני להחלפה בטוחה)"""
    tmp = DB_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(db, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(DB_PATH)

USERS = _load_db()

# ---------- פונקציות עזר לתקשורת ----------
def recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf

def recv_frame(conn: socket.socket) -> bytes:
    """מקבל פריים באורך ידוע מראש (4 בתים ל-header + payload)"""
    hdr = recv_exact(conn, 4)
    ln = int.from_bytes(hdr, "big")
    if ln < 0 or ln > 10_000_000:
        raise ValueError(f"bad frame length {ln}")
    return recv_exact(conn, ln)

def send_frame(conn: socket.socket, payload: bytes) -> None:
    conn.sendall(len(payload).to_bytes(4, "big") + payload)

# ---------- RSA מפתח שרת ----------
PRIV = generate_rsa_private_key()
PUB_PEM = public_key_pem(PRIV.public_key())

# ---------- לוג ----------
def log(msg: str):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

# ---------- טיפול בלקוח ----------
def handle_client(conn: socket.socket, addr):
    log(f"Client connected: {addr}")
    try:
        # שלב 1: קבלת בקשת GET_PUBLIC_KEY
        req = recv_frame(conn)
        if req != b"GET_PUBLIC_KEY":
            raise ValueError(f"Expected GET_PUBLIC_KEY, got: {req[:50]!r}")

        send_frame(conn, PUB_PEM)
        log(f"{addr} -> Sent public key")

        # שלב 2: קבלת מפתח AES מוצפן RSA
        enc_aes = recv_frame(conn)
        aes_key = rsa_decrypt(PRIV, enc_aes)
        log(f"{addr} -> AES session established")

        # שלב 3: תקשורת מוצפנת AES
        while True:
            try:
                enc_msg_bytes = recv_frame(conn)
            except ConnectionError:
                break

            enc_msg = enc_dict_from_bytes(enc_msg_bytes)
            plaintext = decrypt_data(aes_key, enc_msg)
            msg = json.loads(plaintext.decode("utf-8"))
            t = msg.get("type")

            if t == "logout":
                resp = {"ok": True, "bye": True}
                send_frame(conn, enc_dict_to_bytes(encrypt_data(aes_key, json.dumps(resp).encode())))
                log(f"{addr} -> logout")
                break

            elif t == "register":
                username = (msg.get("username") or "").strip()
                salt = msg.get("salt")
                encrypted = msg.get("encrypted")
                if not username:
                    resp = {"ok": False, "error": "username_required"}
                elif not isinstance(salt, str):
                    resp = {"ok": False, "error": "salt_required"}
                elif encrypted is None:
                    resp = {"ok": False, "error": "encrypted_required"}
                elif username in USERS:
                    resp = {"ok": False, "error": "user_exists"}
                else:
                    USERS[username] = {"salt": salt, "encrypted": encrypted}
                    _save_db(USERS)
                    resp = {"ok": True, "username": username}
                    log(f"{addr} -> Registered new user: {username}")

            elif t == "login":
                username = (msg.get("username") or "").strip()
                u = USERS.get(username)
                resp = {"ok": True, "username": username, "salt": u["salt"], "encrypted": u["encrypted"]} \
                    if u else {"ok": False, "error": "user_not_found"}

            elif t == "update_vault":
                username = (msg.get("username") or "").strip()
                encrypted = msg.get("encrypted")
                if not username:
                    resp = {"ok": False, "error": "username_required"}
                elif encrypted is None:
                    resp = {"ok": False, "error": "encrypted_required"}
                elif username not in USERS:
                    resp = {"ok": False, "error": "user_not_found"}
                else:
                    USERS[username]["encrypted"] = encrypted
                    _save_db(USERS)
                    resp = {"ok": True}
                    log(f"{addr} -> Vault updated for user {username}")

            else:
                resp = {"ok": False, "error": f"unknown_type:{t}"}

            # שליחת תגובה מוצפנת
            send_frame(conn, enc_dict_to_bytes(encrypt_data(aes_key, json.dumps(resp).encode())))

    except Exception as e:
        log(f"{addr} error: {e}")
    finally:
        try:
            conn.close()
        finally:
            log(f"Client disconnected: {addr}")

# ---------- Main ----------
def main():
    log(f"Server listening on {HOST}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(100)
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    main()
