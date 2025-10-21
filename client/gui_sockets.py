# client/gui_sockets.py
import os, sys
sys.path.append(os.path.dirname(__file__))                       # secure_channel.py
sys.path.append(os.path.dirname(os.path.dirname(__file__)))      # Encryption.py בשורש

import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import font as tkfont
import json, base64, os as _os

from secure_channel import SecureChannel
from Encryption import derive_key, encrypt_data, decrypt_data

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 6000
CHANNEL = None

# ---------- Theme (Dark) ----------
BG    = "#0f172a"   # slate-900
PANEL = "#111827"   # gray-900
CARD  = "#1f2937"   # gray-800
TEXT  = "#e5e7eb"   # gray-200
MUTED = "#9ca3af"   # gray-400
ACCENT= "#6366f1"   # indigo-500
ACCENT_HO = "#4f46e5"

def apply_theme_and_fonts(root: tk.Tk):
    root.configure(bg=BG)
    style = ttk.Style(root)
    style.theme_use("clam")

    # defaults
    root.option_add("*Font", "TkDefaultFont 11")
    root.option_add("*TEntry*Font", "TkDefaultFont 11")
    root.option_add("*Treeview*Font", "TkDefaultFont 10")
    root.option_add("*Label*Foreground", TEXT)

    # buttons (accent = תכלת)
    style.configure("Accent.TButton",
                    background=ACCENT, foreground="white",
                    padding=(14, 10), relief="flat")
    style.map("Accent.TButton",
              background=[("active", ACCENT_HO), ("pressed", ACCENT_HO)],
              relief=[("pressed", "flat")])

    # entries/frames
    style.configure("TEntry", fieldbackground=CARD, foreground=TEXT, bordercolor="#374151")
    style.configure("Card.TFrame", background=CARD)
    style.configure("Panel.TFrame", background=PANEL)
    style.configure("TFrame", background=BG)

    # table
    style.configure("Vault.Treeview",
                    background=CARD, fieldbackground=CARD, foreground=TEXT,
                    bordercolor=CARD, rowheight=28)
    style.configure("Vault.Treeview.Heading",
                    background="#111827", foreground=TEXT, bordercolor="#111827")
    style.map("Vault.Treeview",
              background=[("selected", "#374151")],
              foreground=[("selected", TEXT)])

    # fonts: copy from default, return names
    base = tkfont.nametofont("TkDefaultFont")
    title_font    = base.copy(); title_font.configure(size=18, weight="bold")
    subtitle_font = base.copy(); subtitle_font.configure(size=11)
    header_font   = base.copy(); header_font.configure(size=16, weight="bold")

    return {"title": title_font.name, "subtitle": subtitle_font.name, "header": header_font.name}

def card(master, padding=16):
    f = ttk.Frame(master, style="Card.TFrame")
    f.configure(padding=padding)
    return f

def center(win, w=480, h=260):
    win.update_idletasks()
    sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
    x = int((sw - w) / 2); y = int((sh - h) / 2)
    win.geometry(f"{w}x{h}+{x}+{y}")

# ---------- Networking ----------
def send_api(msg: dict, expect=True) -> dict:
    try:
        return CHANNEL.request(msg, expect_response=expect)
    except Exception as e:
        return {"ok": False, "error": f"network_error: {e}"}

# ---------- Auth ----------
def register_user(entry_username, entry_password):
    username = entry_username.get().strip()
    master_password = entry_password.get()
    if not username or not master_password:
        messagebox.showerror("Error", "Please enter both username and password")
        return

    empty_vault = {"entries": []}
    salt = _os.urandom(16)
    key = derive_key(master_password, salt)
    encrypted = encrypt_data(key, json.dumps(empty_vault).encode("utf-8"))

    req = {"type": "register", "username": username,
           "salt": base64.b64encode(salt).decode("utf-8"),
           "encrypted": encrypted}
    resp = send_api(req)
    if resp.get("ok"):
        messagebox.showinfo("Register", f"Account created for {username}. You can now login.")
    else:
        messagebox.showerror("Error", resp.get("error") or "Registration failed")

def login_user(entry_username, entry_password, root):
    username = entry_username.get().strip()
    master_password = entry_password.get()
    if not username or not master_password:
        messagebox.showerror("Error", "Please enter both username and password")
        return

    resp = send_api({"type": "login", "username": username})
    if not resp.get("ok"):
        messagebox.showerror("Login Failed", resp.get("error") or "User not found")
        return

    try:
        salt = base64.b64decode(resp["salt"])
        encrypted = resp["encrypted"]
        key = derive_key(master_password, salt)
        databank = json.loads(decrypt_data(key, encrypted).decode("utf-8"))
    except Exception:
        messagebox.showerror("Login Failed", "Incorrect username or password")
        return

    root.destroy()
    open_databank_window(username, master_password, databank)

# ---------- Windows ----------
def open_login_window():
    global CHANNEL
    CHANNEL = SecureChannel(SERVER_HOST, SERVER_PORT).connect()

    root = tk.Tk()
    root.title("DataSecured – Login")

    fonts = apply_theme_and_fonts(root)
    root.minsize(560, 360)
    center(root, 560, 360)

    # titles
    tk.Label(root, text="DataSecured", font=fonts["title"], fg=TEXT,  bg=BG).pack(pady=(18, 2))
    tk.Label(root, text="Secure Password Vault", font=fonts["subtitle"], fg=MUTED, bg=BG).pack(pady=(0, 8))

    # card
    frame = card(root)
    frame.pack(fill="both", expand=True, padx=22, pady=12)

    ttk.Label(frame, text="Username").grid(row=0, column=0, sticky="w", pady=(0, 6))
    e_user = ttk.Entry(frame, width=28); e_user.grid(row=1, column=0, sticky="we", pady=(0, 10))

    ttk.Label(frame, text="Master Password").grid(row=2, column=0, sticky="w")
    e_pass = ttk.Entry(frame, show="*", width=28); e_pass.grid(row=3, column=0, sticky="we", pady=(0, 6))

    # buttons (Accent תכלת) + רווח קטן ביניהם
    btns = ttk.Frame(frame, style="Card.TFrame")
    btns.grid(row=4, column=0, sticky="we", pady=(10,0))
    btns.grid_columnconfigure(0, weight=1, uniform="btns")
    btns.grid_columnconfigure(1, weight=1, uniform="btns")

    ttk.Button(btns, text="Login",    style="Accent.TButton",
               command=lambda: login_user(e_user, e_pass, root)).grid(row=0, column=0, sticky="we", padx=(0, 3))   # ← רווח מימין
    ttk.Button(btns, text="Register", style="Accent.TButton",
               command=lambda: register_user(e_user, e_pass)).grid(row=0, column=1, sticky="we", padx=(3, 0))     # ← רווח משמאל

    root.mainloop()

def open_databank_window(username, master_password, databank):
    win = tk.Tk()
    win.title(f"DataSecured – {username}'s Vault")

    fonts = apply_theme_and_fonts(win)
    center(win, 900, 560)

    # header
    header = ttk.Frame(win, style="Panel.TFrame"); header.pack(fill="x")
    tk.Label(header, text=f"Welcome, {username}!", font=fonts["header"], fg=TEXT, bg=PANEL)\
        .pack(side="left", padx=16, pady=12)

    # table
    tbl_card = card(win, padding=12); tbl_card.pack(fill="both", expand=True, padx=16, pady=(10, 6))
    columns = ("Site", "Username", "Password", "Notes")
    tree = ttk.Treeview(tbl_card, columns=columns, show="headings", style="Vault.Treeview")
    for col in columns:
        tree.heading(col, text=col, anchor="w")
        tree.column(col, anchor="w", stretch=True, width=150)
    tree.grid(row=0, column=0, sticky="nsew")
    tbl_card.rowconfigure(0, weight=1); tbl_card.columnconfigure(0, weight=1)

    vs = ttk.Scrollbar(tbl_card, orient="vertical", command=tree.yview)
    vs.grid(row=0, column=1, sticky="ns"); tree.configure(yscroll=vs.set)

    def _zebra():
        for i, iid in enumerate(tree.get_children()):
            tree.tag_configure("odd", background="#1b2533")
            tree.tag_configure("even", background=CARD)
            tree.item(iid, tags=("odd" if i % 2 else "even",))

    for entry in databank.get("entries", []):
        tree.insert("", "end", values=(entry["site"], entry["username"], entry["password"], entry.get("notes", "")))
    _zebra()

    # controls – כולם תכלת
    controls = card(win); controls.pack(fill="x", padx=16, pady=(0, 14))
    for i in range(5): controls.columnconfigure(i, weight=1)

    ttk.Button(controls, text="Add Entry",     style="Accent.TButton",
               command=lambda: add_entry(tree, _zebra)).grid(row=0, column=0, padx=6, pady=2, sticky="we")
    ttk.Button(controls, text="Edit Entry",    style="Accent.TButton",
               command=lambda: edit_entry(tree, _zebra)).grid(row=0, column=1, padx=6, pady=2, sticky="we")
    ttk.Button(controls, text="Delete Entry",  style="Accent.TButton",
               command=lambda: delete_entry(tree, _zebra)).grid(row=0, column=2, padx=6, pady=2, sticky="we")
    ttk.Button(controls, text="Save to Server",style="Accent.TButton",
               command=lambda: save_to_server(tree, master_password, username)).grid(row=0, column=3, padx=6, pady=2, sticky="we")
    ttk.Button(controls, text="Refresh",       style="Accent.TButton",
               command=lambda: refresh_from_server(tree, master_password, username, _zebra)).grid(row=0, column=4, padx=6, pady=2, sticky="we")

    win.mainloop()

# ---------- Vault ops ----------
def add_entry(tree, zebra_cb):
    top = tk.Toplevel(); top.title("Add Entry")
    apply_theme_and_fonts(top)

    # חלון מעט גדול יותר + הכפתור תמיד נראה
    top.minsize(520, 360)
    center(top, 520, 360)

    frm = card(top, padding=16)
    frm.pack(fill="both", expand=True, padx=16, pady=16)

    # טור יחיד נמתח; נוסיף "שורת ספייסר" שדוחפת את הכפתור למטה
    frm.grid_columnconfigure(0, weight=1)
    frm.grid_rowconfigure(8, weight=1)  # spacer row

    ttk.Label(frm, text="Site").grid(row=0, column=0, sticky="w")
    e_site = ttk.Entry(frm, width=32)
    e_site.grid(row=1, column=0, sticky="we", pady=(0, 8))

    ttk.Label(frm, text="Username").grid(row=2, column=0, sticky="w")
    e_user = ttk.Entry(frm, width=32)
    e_user.grid(row=3, column=0, sticky="we", pady=(0, 8))

    ttk.Label(frm, text="Password").grid(row=4, column=0, sticky="w")
    e_pass = ttk.Entry(frm, width=32)
    e_pass.grid(row=5, column=0, sticky="we", pady=(0, 8))

    ttk.Label(frm, text="Notes").grid(row=6, column=0, sticky="w")
    e_notes = ttk.Entry(frm, width=32)
    e_notes.grid(row=7, column=0, sticky="we")

    # הכפתור ממוקם אחרי שורת הספייסר – תמיד יופיע בתחתית
    ttk.Button(
        frm, text="Save", style="Accent.TButton",
        command=lambda: (_insert(tree, e_site, e_user, e_pass, e_notes), zebra_cb(), top.destroy())
    ).grid(row=9, column=0, sticky="we", pady=(12, 0))

def _insert(tree, e_site, e_user, e_pass, e_notes):
    tree.insert("", "end", values=(e_site.get(), e_user.get(), e_pass.get(), e_notes.get()))

def edit_entry(tree, zebra_cb):
    sel = tree.selection()
    if not sel:
        messagebox.showerror("Error", "Select an entry to edit")
        return
    item = tree.item(sel[0])

    top = tk.Toplevel(); top.title("Edit Entry")
    apply_theme_and_fonts(top)

    # חלון מעט גדול יותר + הכפתור תמיד נראה
    top.minsize(520, 360)
    center(top, 520, 360)

    frm = card(top, padding=16)
    frm.pack(fill="both", expand=True, padx=16, pady=16)

    frm.grid_columnconfigure(0, weight=1)
    frm.grid_rowconfigure(8, weight=1)  # spacer row

    ttk.Label(frm, text="Site").grid(row=0, column=0, sticky="w")
    e_site = ttk.Entry(frm)
    e_site.insert(0, item["values"][0])
    e_site.grid(row=1, column=0, sticky="we", pady=(0, 8))

    ttk.Label(frm, text="Username").grid(row=2, column=0, sticky="w")
    e_user = ttk.Entry(frm)
    e_user.insert(0, item["values"][1])
    e_user.grid(row=3, column=0, sticky="we", pady=(0, 8))

    ttk.Label(frm, text="Password").grid(row=4, column=0, sticky="w")
    e_pass = ttk.Entry(frm)
    e_pass.insert(0, item["values"][2])
    e_pass.grid(row=5, column=0, sticky="we", pady=(0, 8))

    ttk.Label(frm, text="Notes").grid(row=6, column=0, sticky="w")
    e_notes = ttk.Entry(frm)
    e_notes.insert(0, item["values"][3])
    e_notes.grid(row=7, column=0, sticky="we")

    ttk.Button(
        frm, text="Save", style="Accent.TButton",
        command=lambda: (_update(tree, sel[0], e_site, e_user, e_pass, e_notes), zebra_cb(), top.destroy())
    ).grid(row=9, column=0, sticky="we", pady=(12, 0))

def _update(tree, iid, e_site, e_user, e_pass, e_notes):
    tree.item(iid, values=(e_site.get(), e_user.get(), e_pass.get(), e_notes.get()))

def delete_entry(tree, zebra_cb):
    sel = tree.selection()
    if not sel: messagebox.showerror("Error", "Select an entry to delete"); return
    tree.delete(sel[0]); zebra_cb()

def save_to_server(tree, master_password, username):
    entries = []
    for ch in tree.get_children():
        v = tree.item(ch)["values"]
        entries.append({"site": v[0], "username": v[1], "password": v[2], "notes": v[3]})
    databank = {"entries": entries}
    resp = send_api({"type": "login", "username": username})
    if not resp.get("ok"):
        messagebox.showerror("Error", resp.get("error") or "Could not get salt"); return
    salt = base64.b64decode(resp["salt"])
    key = derive_key(master_password, salt)
    encrypted = encrypt_data(key, json.dumps(databank).encode("utf-8"))
    resp2 = send_api({"type": "update_vault", "username": username, "encrypted": encrypted})
    if resp2.get("ok"):
        messagebox.showinfo("Saved", "Data saved to server")
    else:
        messagebox.showerror("Error", resp2.get("error") or "Save failed")

def refresh_from_server(tree, master_password, username, zebra_cb):
    resp = send_api({"type": "login", "username": username})
    if not resp.get("ok"):
        messagebox.showerror("Error", resp.get("error") or "Could not fetch databank"); return
    try:
        salt = base64.b64decode(resp["salt"]); encrypted = resp["encrypted"]
        key = derive_key(master_password, salt)
        databank = json.loads(decrypt_data(key, encrypted).decode("utf-8"))
    except Exception:
        messagebox.showerror("Error", "Failed to decrypt databank"); return
    for ch in tree.get_children(): tree.delete(ch)
    for e in databank.get("entries", []):
        tree.insert("", "end", values=(e["site"], e["username"], e["password"], e.get("notes","")))
    zebra_cb()

# ---------- Main ----------
if __name__ == "__main__":
    open_login_window()
# data secured