import os
import sqlite3
import secrets
import string
import tkinter as tk
from cryptography.fernet import Fernet
import pyperclip  # Zwischenablage-Handling
import bcrypt
import os
from tkinter import simpledialog, messagebox

#  Master-Passwort-Datei definieren
MASTER_PASSWORD_FILE = os.path.join(os.path.expanduser("~"), "Passbär", "master_password.hash")

#  Passwort sicher speichern & vergleichen mit Hashing
def hash_password(password):
    """ Erstellt einen sicheren Hash für das Passwort. """
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed_password):
    """ Überprüft, ob das eingegebene Passwort mit dem gespeicherten Hash übereinstimmt. """
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

#  Master-Passwort setzen oder überprüfen
def check_master_password():
    """ Überprüft oder setzt das Master-Passwort mit sicherem Hashing und doppelter Eingabe zur Überprüfung. """
    if not os.path.exists(MASTER_PASSWORD_FILE):
        while True:
            master_password = simpledialog.askstring("Master-Passwort setzen", "Erstelle ein Master-Passwort:", show='*')
            confirm_password = simpledialog.askstring("Master-Passwort bestätigen", "Gib dein Master-Passwort erneut ein:", show='*')

            if not master_password or not confirm_password:
                messagebox.showinfo("Abbruch", "Master-Passwort-Eingabe wurde abgebrochen.")
                return False
            
            if master_password.strip() != confirm_password.strip():
                messagebox.showerror("Fehler", "Passwörter stimmen nicht überein! Bitte erneut eingeben.")
                
            else:
                hashed_password = hash_password(master_password)
                with open(MASTER_PASSWORD_FILE, "w") as file:
                    file.write(hashed_password)
                messagebox.showinfo("Erfolg", "Master-Passwort wurde erfolgreich gesetzt.")
                break

    with open(MASTER_PASSWORD_FILE, "r") as file:
        saved_hashed_password = file.read().strip()

    master_password = simpledialog.askstring("Master-Passwort", "Bitte geben sie das Master-Password ein : ", show='*')

    if master_password is None:
        messagebox.showinfo("Abbruch", "Master-Passwort-Eingabe wurde abgebrochen.")
        return False

    if verify_password(master_password.strip(), saved_hashed_password):
        return True
    else:
        messagebox.showerror("Fehler", "Falsches Master-Password ! ")
        return False

#  Automatisch Speicherort setzen
STORAGE_FOLDER = os.path.join(os.path.expanduser("~"), "Passbär")
KEYS_FOLDER = os.path.join(STORAGE_FOLDER, "keys")
DB_FOLDER = os.path.join(STORAGE_FOLDER, "database")

#  Ordner erstellen, falls nicht vorhanden
os.makedirs(KEYS_FOLDER, exist_ok=True)
os.makedirs(DB_FOLDER, exist_ok=True)

#  Schlüssel- und Datenbankpfad setzen
KEY_FILE = os.path.join(KEYS_FOLDER, "key.key")
DB_FILE = os.path.join(DB_FOLDER, "passwords.db")
MASTER_PASSWORD_FILE = os.path.join(STORAGE_FOLDER, "master_password.hash")

print(f"✅ Speicherorte:\n- Hauptordner: {STORAGE_FOLDER}\n- Schlüssel: {KEYS_FOLDER}\n- Datenbank: {DB_FOLDER}")

#  Schlüssel generieren oder laden
def generate_key():
    """ Lädt vorhandenen Schlüssel oder erstellt einen neuen. """
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as file:
            key = file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as file:
            file.write(key)
    return Fernet(key)

cipher_suite = generate_key()

# Passwort sicher speichern & vergleichen mit Hashing
def hash_password(password):
    """ Erstellt einen sicheren Hash für das Passwort. """
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, hashed_password):
    """ Überprüft, ob das eingegebene Passwort mit dem gespeicherten Hash übereinstimmt. """
    return bcrypt.checkpw(password.encode(), hashed_password.encode())

#  SQLite-Datenbank erstellen
def create_database():
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                service TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
        """)

create_database()

#  Passwort verschlüsseln & entschlüsseln
def encrypt_password(password):
    return cipher_suite.encrypt(password.encode())

def decrypt_password(encrypted_password):
    return cipher_suite.decrypt(encrypted_password.encode()).decode()

#  Passwort speichern mit manueller Eingabe
def save_custom_password(service, custom_password):
    encrypted = encrypt_password(custom_password)
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("INSERT INTO passwords (service, password) VALUES (?, ?)", (service, encrypted.decode()))
        pyperclip.copy(custom_password)
        masked_password_custom = "●" * len(custom_password)
        messagebox.showinfo("Passwort gespeichert", f"Passwort für {service}: {masked_password_custom}\n(Das Passwort wurde in die Zwischenablage kopiert!)")
    except sqlite3.IntegrityError:
        messagebox.showerror("Fehler", f"Der Dienstname '{service}' existiert bereits!")


# Sicheres Passwort generieren
def generate_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

# Passwort speichern und in die Zwischenablage kopieren
def save_password(service, password):
    encrypted = encrypt_password(password)
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("INSERT INTO passwords (service, password) VALUES (?, ?)", (service, encrypted.decode()))
        pyperclip.copy(password)
        masked_password = "●" * len(password)
        messagebox.showinfo("Passwort gespeichert", f"Passwort für {service}: {masked_password}\n(Das Passwort wurde in die Zwischenablage kopiert!)")
    except sqlite3.IntegrityError:
        messagebox.showerror("Fehler", f"Der Dienstname '{service}' existiert bereits!")

def load_passwords():
    if any(isinstance(w, tk.Toplevel) for w in tk._default_root.children.values()):
        return  # Kein neues Fenster öffnen, wenn schon eins da ist

    def refresh_list(filter_text=""):
        for widget in content.winfo_children():
            widget.destroy()

        filtered_rows = [row for row in rows if filter_text.lower() in row[1].lower()]

        if not filtered_rows:
            tk.Label(content, text="Keine passenden Einträge gefunden.", bg="#2E3B4E", fg="white").pack(pady=20)
            return

        for row in filtered_rows:
            service = row[1]
            pw_id = row[0]

            item_frame = tk.Frame(content, bg="#2E3B4E")
            item_frame.pack(fill="x", pady=5)

            btn_copy = tk.Button(item_frame, text=service, font=("Arial", 8), bg="#2196F3", fg="white",
                                 command=lambda id=pw_id: copy_password(id))
            btn_copy.pack(side="left", expand=True, fill="x", padx=(0, 5))

            btn_delete = tk.Button(item_frame, text="Löschen", font=("Arial", 8), bg="#f44336", fg="white",
                                   command=lambda id=pw_id, f=item_frame: delete_password(id, f))
            btn_delete.pack(side="right")

    def copy_password(selected_id):
        for row in rows:
            if row[0] == selected_id:
                service, encrypted_password = row[1], row[2]
                password = decrypt_password(encrypted_password)
                pyperclip.copy(password)
                masked_password_copy = "●" * len(password)
                messagebox.showinfo("Passwort kopiert", f"Passwort für {service}: {masked_password_copy}\n(Das Passwort wurde in die Zwischenablage kopiert!)")
                break

    def delete_password(selected_id, frame_to_destroy):
        with sqlite3.connect(DB_FILE) as conn:
            conn.execute("DELETE FROM passwords WHERE id=?", (selected_id,))
            conn.commit()

        messagebox.showinfo("Passwort gelöscht", "Das Passwort wurde erfolgreich gelöscht!")
        frame_to_destroy.destroy()

    with sqlite3.connect(DB_FILE) as conn:
        rows = conn.execute("SELECT id, service, password FROM passwords").fetchall()

    selection_window = tk.Toplevel()
    selection_window.title("Gespeicherte Passwörter")
    selection_window.geometry("350x500")
    selection_window.configure(bg="#2E3B4E")

    header = tk.Frame(selection_window, bg="#1F2A35", height=60)
    header.pack(fill="x")
    tk.Label(header, text="🔒 Gespeicherte Passwörter", font=("Arial", 16, "bold"), bg="#1F2A35", fg="#F9AA33").pack(pady=15)

    # Suchfeld mit Lupe
    search_frame = tk.Frame(selection_window, bg="#2E3B4E")
    search_frame.pack(pady=20, padx=10, fill="x")

    tk.Label(search_frame, text="App: ", bg="#2E3B4E", fg="white", font=("Arial", 10)).pack(side="left", padx=(0, 5))

    search_var = tk.StringVar()
    search_entry = tk.Entry(
        search_frame,
        textvariable=search_var,
        bg="#1F2A35",
        fg="white",
        insertbackground="white",
        relief="flat"
    )
    search_entry.pack(side="left", fill="x", expand=True)

    # Filterung bei Texteingabe
    search_var.trace_add("write", lambda *args: refresh_list(search_var.get()))

    content = tk.Frame(selection_window, bg="#2E3B4E", padx=10, pady=10)
    content.pack(fill="both", expand=True)

    refresh_list()

def create_gui():
    if not check_master_password():
        return

    root = tk.Tk()
    root.title("Passbär")
    root.geometry("350x350")
    root.configure(bg="#2E3B4E")
    root.minsize(350, 350)  # Set a minimum size for better responsiveness
 

    # Header Frame
    header_frame = tk.Frame(root, bg="#1F2A35", height=60)
    header_frame.pack(fill="x")
    tk.Label(header_frame, text="🔑 Passbär", font=("Arial", 16, "bold"), bg="#1F2A35", fg="#F9AA33").pack(pady=15)

    # Content Frame
    content_frame = tk.Frame(root, padx=10, pady=10, bg="#2E3B4E")
    content_frame.pack(fill="both", expand=True)

    # Styling for Entry Fields
    entry_style = {"font": ("Arial", 8), "bg": "#1F2A35", "fg": "white", "insertbackground": "white", "relief": "flat"}

    tk.Label(content_frame, text="App: ", font=("Arial", 8, "bold"), fg="white", bg="#2E3B4E").grid(row=0, column=0, sticky="w", pady=10)
    service_entry = tk.Entry(content_frame, **entry_style)
    service_entry.grid(row=0, column=1, sticky="ew", pady=5)

    tk.Label(content_frame, text="Key: ", font=("Arial", 8, "bold"), fg="white", bg="#2E3B4E").grid(row=1, column=0, sticky="w", pady=5)
    password_entry = tk.Entry(content_frame, **entry_style, show="*")
    password_entry.grid(row=1, column=1, sticky="ew", pady=10)

    # Grid Configuration for Responsiveness
    content_frame.grid_columnconfigure(1, weight=1)

    def generate_and_save():
        service = service_entry.get().strip()
        if not service:
            messagebox.showerror("Fehler", "Bitte App eingeben!")
            return
        password = generate_password()
        save_password(service, password)
        service_entry.delete(0, tk.END)

    def save_custom():
        service = service_entry.get().strip()
        custom_password = password_entry.get().strip()
        if not service or not custom_password:
            messagebox.showerror("Fehler", "Bitte App und Key eingeben!")
            return
        save_custom_password(service, custom_password)
        service_entry.delete(0, tk.END)
        password_entry.delete(0, tk.END)

    button_style = {"font": ("Arial", 8, "bold"), "relief": "flat", "bd": 5, "padx": 8, "pady": 2, "cursor": "hand2"}

    # Button Frame
    button_frame = tk.Frame(content_frame, bg="#2E3B4E")
    button_frame.grid(row=3, column=0, columnspan=2, pady=8, sticky="ew")

    tk.Button(button_frame, text="Key generieren und speichern", bg="#20b2aa", fg="white", command=generate_and_save, **button_style).pack(fill="x", pady=5)
    tk.Button(button_frame, text="Eigenen Key speichern", bg="#4CAF50", fg="white", command=save_custom, **button_style).pack(fill="x", pady=5)
    tk.Button(button_frame, text="Gespeicherte Keys anzeigen", bg="#F9AA33", fg="white", command=load_passwords, **button_style).pack(fill="x", pady=5)
    tk.Button(button_frame, text="Beenden", bg="#ff0000", fg="white", command=root.quit, **button_style).pack(fill="x", pady=5)

    
    root.mainloop()

# GUI starten
if __name__ == "__main__":
    create_gui() 