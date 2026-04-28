# client/gui_sockets.py
import os, sys, threading, json, base64, os as _os
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import font as tkfont

# הוספת נתיבים לייבוא
sys.path.append(os.path.dirname(__file__))
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from secure_channel import SecureChannel
from Encryption import derive_key, encrypt_data, decrypt_data

# הגדרות שרת
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 6000
CHANNEL = None

# ---------- פלטת צבעים מודרנית (Professional Dark Theme) ----------
BG_MAIN = "#0f172a"  # רקע עמוק
BG_CARD = "#1e293b"  # רקע כרטיסים
ACCENT = "#6366f1"  # צבע דגש (Indigo)
ACCENT_HO = "#818cf8"  # הובר כפתורים
TEXT_MAIN = "#f8fafc"  # טקסט לבן רך
TEXT_MUTED = "#94a3b8"  # טקסט משני
SUCCESS = "#22c55e"  # ירוק הצלחה
ERROR = "#ef4444"  # אדום שגיאה


def apply_modern_theme(root):
    root.configure(bg=BG_MAIN)
    style = ttk.Style(root)
    style.theme_use("clam")

    # הגדרות פונטים
    default_font = ("Segoe UI", 10)
    bold_font = ("Segoe UI", 10, "bold")
    header_font = ("Segoe UI", 20, "bold")

    # עיצוב כפתורים
    style.configure("Accent.TButton", font=bold_font, background=ACCENT, foreground="white", borderwidth=0, padding=10)
    style.map("Accent.TButton", background=[("active", ACCENT_HO)])

    style.configure("Secondary.TButton", font=bold_font, background="#334155", foreground="white", borderwidth=0,
                    padding=10)
    style.map("Secondary.TButton", background=[("active", "#475569")])

    # עיצוב שדות קלט
    style.configure("TEntry", fieldbackground=BG_CARD, foreground="white", insertcolor="white", borderwidth=0)

    # עיצוב טבלה (Treeview) - כולל ביטול הלבן במעבר עכבר
    style.configure("Treeview",
                    background=BG_CARD,
                    fieldbackground=BG_CARD,
                    foreground=TEXT_MAIN,
                    rowheight=35,
                    borderwidth=0,
                    font=default_font)

    style.configure("Treeview.Heading",
                    background="#334155",
                    foreground="white",
                    font=bold_font,
                    borderwidth=0)

    # כאן הסרנו את שינוי הצבע במעבר עכבר (active/hover) כדי למנוע את הצבע הלבן
    style.map("Treeview",
              background=[("selected", ACCENT)],
              foreground=[("selected", "white")])

    return {"header": header_font, "bold": bold_font, "default": default_font}


def center_window(win, w, h):
    sw, sh = win.winfo_screenwidth(), win.winfo_screenheight()
    x, y = int((sw - w) / 2), int((sh - h) / 2)
    win.geometry(f"{w}x{h}+{x}+{y}")


# ---------- לוגיקת AI לחוזק סיסמה ----------
def analyze_password_strength(password):
    if not password: return 0, "Empty"
    if len(password) < 8: return 1, "Too Short"

    types = [any(c.isupper() for c in password), any(c.islower() for c in password),
             any(c.isdigit() for c in password), any(not c.isalnum() for c in password)]
    score = sum(types)

    if score >= 3 and len(password) >= 12: return 4, "Strong (AI Verified)"
    if score >= 2: return 2, "Moderate"
    return 1, "Weak"


# ---------- חלון לוגין ----------
def open_login_window():
    global CHANNEL
    try:
        CHANNEL = SecureChannel(SERVER_HOST, SERVER_PORT).connect()
    except:
        messagebox.showerror("Connection Error", "Server is offline. Start socket_server.py first.")
        return

    root = tk.Tk()
    root.title("DataSecured v2.1")
    fonts = apply_modern_theme(root)
    center_window(root, 450, 500)

    tk.Label(root, text="DataSecured", font=fonts["header"], fg=ACCENT, bg=BG_MAIN).pack(pady=(40, 5))
    tk.Label(root, text="Advanced AI Password Manager", font=fonts["default"], fg=TEXT_MUTED, bg=BG_MAIN).pack(
        pady=(0, 30))

    container = tk.Frame(root, bg=BG_MAIN)
    container.pack(padx=50, fill="x")

    tk.Label(container, text="Username", font=fonts["bold"], fg=TEXT_MAIN, bg=BG_MAIN).pack(anchor="w")
    e_user = ttk.Entry(container);
    e_user.pack(fill="x", pady=(5, 15))

    tk.Label(container, text="Master Password", font=fonts["bold"], fg=TEXT_MAIN, bg=BG_MAIN).pack(anchor="w")
    e_pass = ttk.Entry(container, show="*");
    e_pass.pack(fill="x", pady=(5, 25))

    ttk.Button(container, text="Login to Vault", style="Accent.TButton",
               command=lambda: login_task(e_user, e_pass, root)).pack(fill="x", pady=5)

    ttk.Button(container, text="Create New Account", style="Secondary.TButton",
               command=lambda: register_task(e_user, e_pass)).pack(fill="x", pady=5)

    root.mainloop()


# ---------- חלון הכספת הראשי ----------
def open_databank_window(username, master_password, databank):
    win = tk.Tk()
    win.title(f"Vault: {username}")
    fonts = apply_modern_theme(win)
    center_window(win, 1000, 650)

    top_bar = tk.Frame(win, bg=BG_CARD, height=70)
    top_bar.pack(fill="x")
    top_bar.pack_propagate(False)
    tk.Label(top_bar, text=f"Welcome, {username}", font=fonts["bold"], fg=TEXT_MAIN, bg=BG_CARD).pack(side="left",
                                                                                                      padx=20)

    content = tk.Frame(win, bg=BG_MAIN, padx=20, pady=20)
    content.pack(fill="both", expand=True)

    columns = ("Site", "Username", "Password", "Notes")
    tree = ttk.Treeview(content, columns=columns, show="headings")
    for col in columns:
        tree.heading(col, text=col)
        tree.column(col, width=150)
    tree.pack(fill="both", expand=True)

    btn_frame = tk.Frame(content, bg=BG_MAIN, pady=20)
    btn_frame.pack(fill="x")

    for i in range(5): btn_frame.columnconfigure(i, weight=1)

    ttk.Button(btn_frame, text="✚ Add", style="Accent.TButton", command=lambda: add_entry_ui(tree)).grid(row=0,
                                                                                                         column=0,
                                                                                                         padx=5)
    ttk.Button(btn_frame, text="✎ Edit", style="Secondary.TButton", command=lambda: edit_entry_ui(tree)).grid(row=0,
                                                                                                              column=1,
                                                                                                              padx=5)
    ttk.Button(btn_frame, text="🗑 Delete", style="Secondary.TButton", command=lambda: delete_entry(tree)).grid(row=0,
                                                                                                               column=2,
                                                                                                               padx=5)
    ttk.Button(btn_frame, text="💾 Save All", style="Accent.TButton",
               command=lambda: save_task(tree, master_password, username)).grid(row=0, column=3, padx=5)
    ttk.Button(btn_frame, text="🔄 Refresh", style="Secondary.TButton",
               command=lambda: refresh_task(tree, master_password, username)).grid(row=0, column=4, padx=5)

    for e in databank.get("entries", []):
        tree.insert("", "end", values=(e["site"], e["username"], e["password"], e.get("notes", "")))

    win.mainloop()


# ---------- UI Helpers ----------
def add_entry_ui(tree):
    top = tk.Toplevel();
    top.title("Add New Entry")
    fonts = apply_modern_theme(top)
    center_window(top, 400, 450)
    frm = tk.Frame(top, bg=BG_MAIN, padx=30, pady=30);
    frm.pack(fill="both", expand=True)

    tk.Label(frm, text="Site", bg=BG_MAIN, fg=TEXT_MUTED).pack(anchor="w")
    e_site = ttk.Entry(frm);
    e_site.pack(fill="x", pady=(0, 15))
    tk.Label(frm, text="Username", bg=BG_MAIN, fg=TEXT_MUTED).pack(anchor="w")
    e_user = ttk.Entry(frm);
    e_user.pack(fill="x", pady=(0, 15))
    tk.Label(frm, text="Password", bg=BG_MAIN, fg=TEXT_MUTED).pack(anchor="w")
    e_pass = ttk.Entry(frm);
    e_pass.pack(fill="x", pady=(0, 5))

    ai_lbl = tk.Label(frm, text="AI Strength: -", bg=BG_MAIN, fg=TEXT_MUTED, font=("Segoe UI", 9, "bold"))
    ai_lbl.pack(anchor="w", pady=(0, 15))

    def on_type(e):
        s, m = analyze_password_strength(e_pass.get())
        color = {0: TEXT_MUTED, 1: ERROR, 2: "#eab308", 4: SUCCESS}.get(s)
        ai_lbl.config(text=f"AI Strength: {m}", fg=color)

    e_pass.bind("<KeyRelease>", on_type)

    ttk.Button(frm, text="Add to Vault", style="Accent.TButton",
               command=lambda: [tree.insert("", "end", values=(e_site.get(), e_user.get(), e_pass.get(), "")),
                                top.destroy()]).pack(fill="x", pady=10)


def edit_entry_ui(tree):
    sel = tree.selection()
    if not sel: return
    item_vals = tree.item(sel[0])["values"]

    top = tk.Toplevel();
    top.title("Edit Entry")
    fonts = apply_modern_theme(top)
    center_window(top, 400, 450)
    frm = tk.Frame(top, bg=BG_MAIN, padx=30, pady=30);
    frm.pack(fill="both", expand=True)

    e_site = ttk.Entry(frm);
    e_site.insert(0, item_vals[0]);
    e_site.pack(fill="x", pady=(10, 15))
    e_user = ttk.Entry(frm);
    e_user.insert(0, item_vals[1]);
    e_user.pack(fill="x", pady=(0, 15))
    e_pass = ttk.Entry(frm);
    e_pass.insert(0, item_vals[2]);
    e_pass.pack(fill="x", pady=(0, 15))

    ttk.Button(frm, text="Update Entry", style="Accent.TButton",
               command=lambda: [tree.item(sel[0], values=(e_site.get(), e_user.get(), e_pass.get(), "")),
                                top.destroy()]).pack(fill="x", pady=10)


def delete_entry(tree):
    for s in tree.selection(): tree.delete(s)


# ---------- Threaded Tasks ----------
def login_task(e_u, e_p, root):
    def run():
        u, p = e_u.get(), e_p.get()
        resp = CHANNEL.request({"type": "login", "username": u})
        if resp.get("ok"):
            try:
                key = derive_key(p, base64.b64decode(resp["salt"]))
                db = json.loads(decrypt_data(key, resp["encrypted"]).decode())
                root.after(0, lambda: [root.destroy(), open_databank_window(u, p, db)])
            except:
                messagebox.showerror("Error", "Wrong Password")
        else:
            messagebox.showerror("Error", "User not found")

    threading.Thread(target=run, daemon=True).start()


def register_task(e_u, e_p):
    def run():
        u, p = e_u.get(), e_p.get()
        salt = _os.urandom(16)
        key = derive_key(p, salt)
        enc = encrypt_data(key, json.dumps({"entries": []}).encode())
        resp = CHANNEL.request(
            {"type": "register", "username": u, "salt": base64.b64encode(salt).decode(), "encrypted": enc})
        if resp.get("ok"):
            messagebox.showinfo("Success", "Account Created!")
        else:
            messagebox.showerror("Error", "User exists")

    threading.Thread(target=run, daemon=True).start()


def save_task(tree, p, u):
    def run():
        entries = [tree.item(c)["values"] for c in tree.get_children()]
        data = [{"site": e[0], "username": e[1], "password": e[2], "notes": e[3]} for e in entries]
        resp = CHANNEL.request({"type": "login", "username": u})
        key = derive_key(p, base64.b64decode(resp["salt"]))
        enc = encrypt_data(key, json.dumps({"entries": data}).encode())
        if CHANNEL.request({"type": "update_vault", "username": u, "encrypted": enc}).get("ok"):
            messagebox.showinfo("Saved", "Vault synced to cloud!")

    threading.Thread(target=run, daemon=True).start()


def refresh_task(tree, p, u):
    def run():
        resp = CHANNEL.request({"type": "login", "username": u})
        key = derive_key(p, base64.b64decode(resp["salt"]))
        db = json.loads(decrypt_data(key, resp["encrypted"]).decode())
        tree.after(0, lambda: [tree.delete(*tree.get_children()),
                               [tree.insert("", "end", values=(e["site"], e["username"], e["password"], e["notes"])) for
                                e in db["entries"]]])

    threading.Thread(target=run, daemon=True).start()


if __name__ == "__main__":
    open_login_window()