import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from pathlib import Path
import os, shutil, secrets, string, pyzipper, smtplib, ssl, email
import traceback  

from dotenv import load_dotenv
load_dotenv()

# Drag-and-drop setup
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    has_dnd = True
    window = TkinterDnD.Tk()
except ImportError:
    has_dnd = False
    window = tk.Tk()

# GUI variables
file_path_encrypt = tk.StringVar()
file_path_decrypt = tk.StringVar()
mode = tk.StringVar(value="Symmetric")  # mode toggle

# Constants
user_home = str(Path.home())
current_path = Path.home()
current_dir = Path.home()  # Track navigation state
current_decrypt_dir = Path.home()  # Track decryption navigation state


def get_files_in_directory(directory):
    return [str(f) for f in Path(directory).iterdir() if not f.name.startswith('.')]

recent_files = []
Green, Blue, Red, White = "#239b56", "#5dade2", "#e74c3c", "#d0d3d4"

# Window setup
window.title("Encrypt Files & Folders")
window.geometry("520x380")
window.resizable(False, False)

# === RSA Key Helpers ===
def generate_rsa_keys():
    if not Path("rsa_keys/private.pem").exists():
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub = priv.public_key()
        os.makedirs("rsa_keys", exist_ok=True)
        priv_p = priv.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption())
        pub_p = pub.public_bytes(serialization.Encoding.PEM,
                                serialization.PublicFormat.SubjectPublicKeyInfo)
        Path("rsa_keys/private.pem").write_bytes(priv_p)
        Path("rsa_keys/public.pem").write_bytes(pub_p)

def load_rsa_keys():
    priv = serialization.load_pem_private_key(Path("rsa_keys/private.pem").read_bytes(), None)
    pub = serialization.load_pem_public_key(Path("rsa_keys/public.pem").read_bytes())
    return priv, pub

# === Symmetric & Hybrid Helpers ===
def zip_key_with_password(key_file):
    pwd = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(16))
    base = Path(key_file).stem
    zip_name = f"{base}_key.zip"
    pwd_txt = f"{base}_pwd.txt"
    with pyzipper.AESZipFile(zip_name, 'w', compression=pyzipper.ZIP_LZMA) as zf:
        zf.setpassword(pwd.encode())
        zf.setencryption(pyzipper.WZ_AES, nbits=256)
        zf.write(key_file, arcname=Path(key_file).name)
    Path("secure_keys").mkdir(exist_ok=True)
    shutil.move(zip_name, f"secure_keys/{zip_name}")
    with open(pwd_txt, "w") as f:
        f.write(pwd)
    shutil.move(pwd_txt, f"secure_keys/{pwd_txt}")
    return f"secure_keys/{zip_name}", pwd

# === Emails ===
def ask_and_send_email(zipfile, password):
    dlg = tk.Toplevel(window)
    dlg.title("Send Key via Email")
    tk.Label(dlg, text="Recipient Email:").grid(row=0, column=0, padx=5, pady=5)
    reci = tk.StringVar()
    tk.Entry(dlg, textvariable=reci).grid(row=0, column=1, padx=5, pady=5)
    def on_send():
        try:
            send_email(reci.get(), zipfile, password)
            messagebox.showinfo("Email Sent", "✅ Keyfile emailed.")
            dlg.destroy()
        except Exception as e:
            messagebox.showerror("Email Error", str(e))
    tk.Button(dlg, text="Send", command=on_send).grid(row=1, column=0, columnspan=2, pady=5)
    dlg.grab_set()
    dlg.wait_window()

def send_email(to, attachment, password):
    smtp_server = os.getenv("SMTP_SERVER")
    port = int(os.getenv("SMTP_PORT"))
    sender_email = os.getenv("EMAIL_USER")
    sender_pwd = os.getenv("EMAIL_PASS")

    msg = email.message.EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = sender_email, to, "Your Encrypted Keyfile"
    msg.set_content(f"""
Hello,

Please find attached your encrypted keyfile. The password to open the ZIP is:
{password}

⚠️ Important: This key is required to decrypt your file.

Steps to decrypt your file:
1. Extract the ZIP file. Enter the password when prompted.
2. Open the provided decryption tool.
3. In the tool, select your .enc file (e.g., mydoc.pdf.enc).
4. When prompted, select the key file you extracted from the ZIP.
5. The original file will be restored in the same folder.

Let me know if you have any trouble.

Best regards,
Secure Encryption App
""")

    with open(attachment, "rb") as f:
        content = f.read()
    msg.add_attachment(content, maintype="application", subtype="zip", filename=Path(attachment).name)

    context = ssl.create_default_context()
    with smtplib.SMTP(smtp_server, port) as smtp:
        smtp.ehlo()
        smtp.starttls(context=context)
        smtp.login(sender_email, sender_pwd)
        smtp.send_message(msg)


# === Core Actions ===
def encrypt_action():
    path = file_path_encrypt.get()
    if not path:
        return messagebox.showwarning("Warning", "Select file/folder to encrypt.")

    try:
        if os.path.isdir(path):
            zipped = shutil.make_archive(path.rstrip(os.sep), 'zip', path)
            print("📦 Folder zipped as:", zipped)
            path = zipped

        # Generate Fernet key and encrypt file contents
        fkey = Fernet.generate_key()
        file_data = Path(path).read_bytes()
        print(f"📄 Original file size: {len(file_data)} bytes")

        ciphertext = Fernet(fkey).encrypt(file_data)
        enc_file = path + ".enc"

        # Write the encrypted file
        Path(enc_file).write_bytes(ciphertext)
        print("✅ Encrypted file saved as:", enc_file)

        key_filename = ""
        if mode.get() == "Hybrid":
            generate_rsa_keys()
            _, pub = load_rsa_keys()
            ek = pub.encrypt(fkey, padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))
            key_filename = Path("keys") / (Path(path).name + ".hybrid.key")
            os.makedirs("keys", exist_ok=True)
            key_filename.write_bytes(ek)
        else:
            os.makedirs("keys", exist_ok=True)
            key_filename = Path("keys") / (Path(path).name + ".sym.key")
            key_filename.write_bytes(fkey)

        zipf, pwd = zip_key_with_password(str(key_filename))
        messagebox.showinfo("Success", f"Encrypted saved: {enc_file}")
        if messagebox.askyesno("Email Keyfile", "Would you like to email the encrypted key file now?"):
            ask_and_send_email(zipf, pwd)

    except Exception as e:
        traceback.print_exc()  # ← This shows real error in terminal
        err = str(e).strip()
        if not err:
            err = "An unknown error occurred during decryption."
        messagebox.showerror("Decryption Error", f"❌ {err}")




def decrypt_action():
    path = file_path_decrypt.get()
    if not path:
        return messagebox.showwarning("Warning", "Select a file (.enc) to decrypt.")

    keyf = filedialog.askopenfilename(title="Select Encrypted Key")
    if not keyf:
        return messagebox.showwarning("Warning", "Select a key file to proceed.")

    if os.path.isdir(keyf):
        return messagebox.showerror("Decryption Error", f"'{keyf}' is a directory, not a key file.")
    elif not os.path.isfile(keyf):
        return messagebox.showerror("Decryption Error", f"'{keyf}' is not a valid file.")

    try:
        kb = Path(keyf).read_bytes()

        # Check if this is a hybrid key (RSA-encrypted Fernet key)
        if keyf.endswith(".hybrid.key"):
            priv, _ = load_rsa_keys()
            fkey = priv.decrypt(kb, padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            ))
        else:
            fkey = kb
            # Validate Fernet key (only for symmetric)
            try:
                Fernet(fkey)
            except Exception:
                return messagebox.showerror("Decryption Error", "The selected key is not a valid Fernet key.")

        # Decrypt the file
        dec = Fernet(fkey).decrypt(Path(path).read_bytes())
        out = path.replace(".enc", ".decrypted")
        Path(out).write_bytes(dec)
        messagebox.showinfo("Decrypted", f"✅ File successfully decrypted and saved as:\n{out}")

    except Exception as e:
        err = str(e).strip()
        if not err:
            err = "An unknown error occurred during decryption."
        messagebox.showerror("Decryption Error", f"❌ {err}")



def refresh_dropdowns(event=None):
    global current_dir, current_decrypt_dir
    try:
        if event and event.widget == encrypt_combo:
            files = get_files_in_directory(current_dir)
            encrypt_combo['values'] = ["../ (⬆️ Up One Level)"] + files
        elif event and event.widget == decrypt_combo:
            files = get_files_in_directory(current_decrypt_dir)
            decrypt_combo['values'] = ["../ (⬆️ Up One Level)"] + files
    except FileNotFoundError as e:
        messagebox.showerror("Folder Not Found", f"❌ {e}")

def on_encrypt_select(event):
    selected = encrypt_combo.get()

    if selected == "../ (⬆️ Up One Level)":
        go_up_directory()
        return

    if Path(selected).is_dir():
        if selected != str(current_dir):
            update_encrypt_combo(selected)
    else:
        file_path_encrypt.set(selected)

        
def go_up_directory():
    global current_dir
    if current_dir.parent != current_dir:
        current_dir = current_dir.parent
        update_encrypt_combo()


def update_encrypt_combo(path=None):
    global current_dir
    if path:
        new_path = Path(path)
        if new_path.is_dir():
            current_dir = new_path

    files = get_files_in_directory(current_dir)
    files = [f"{'📁 ' if Path(f).is_dir() else ''}{f}" for f in get_files_in_directory(current_dir)]

    # Add "Up One Level" entry at the top
    display_list = ["../ (⬆️ Up One Level)"] + files

    encrypt_combo['values'] = display_list
    

def update_decrypt_combo(path=None):
    global current_decrypt_dir
    if path:
        new_path = Path(path)
        if new_path.is_dir():
            current_decrypt_dir = new_path

    files = get_files_in_directory(current_decrypt_dir)
    files = [f"{'📁 ' if Path(f).is_dir() else ''}{f}" for f in get_files_in_directory(current_decrypt_dir)]
    display_list = ["../ (⬆️ Up One Level)"] + files

    decrypt_combo['values'] = display_list

    
def go_to_folder_encrypt():
    global current_dir
    selected = filedialog.askdirectory(title="Select Folder to Browse")
    if selected:
        current_dir = Path(selected)
        update_encrypt_combo()
        
def go_to_folder_decrypt():
    global decrypt_dir
    selected = filedialog.askdirectory(title="Select Folder to Browse")
    if selected:
        decrypt_dir = Path(selected)
        update_decrypt_combo()
        
def on_decrypt_select(event):
    selected = decrypt_combo.get()

    if selected == "../ (⬆️ Up One Level)":
        go_up_decrypt_directory()
        return

    if Path(selected).is_dir():
        if selected != str(current_decrypt_dir):
            update_decrypt_combo(selected)
    else:
        file_path_decrypt.set(selected)
    
def go_up_decrypt_directory():
    global current_decrypt_dir
    if current_decrypt_dir.parent != current_decrypt_dir:
        current_decrypt_dir = current_decrypt_dir.parent
        update_decrypt_combo()

# === UI Layout ===
tk.Label(window, text="Encryption Mode:", font=("Arial 12 bold")).pack(anchor="w", padx=5, pady=(5, 0))
tk.Radiobutton(window, text="Symmetric", variable=mode, value="Symmetric").pack(anchor="w", padx=20)
tk.Radiobutton(window, text="Hybrid (RSA + Fernet)", variable=mode, value="Hybrid").pack(anchor="w", padx=20)

tk.Label(window, text="Select File or Folder to Encrypt :", font=("Arial 12 bold")).pack(anchor="w", padx=5, pady=(5, 0))
def drop_e(event):
    file_path_encrypt.set(event.data)
    

encrypt_combo = ttk.Combobox(window, textvariable=file_path_encrypt, width=100)
encrypt_combo.pack(padx=5)
if has_dnd:
    encrypt_combo.drop_target_register(DND_FILES)
    encrypt_combo.dnd_bind('<<Drop>>', drop_e)

tk.Button(window, text="Encryption", bg=Blue, fg=Green, command=encrypt_action, width=15).pack(anchor="w", padx=5, pady=5)

tk.Canvas(window, width=480, height=2, bg=Red, highlightthickness=0).pack(pady=10)

tk.Label(window, text="Select File or Folder to Decrypt:", font=("Arial 12 bold")).pack(anchor="w", padx=5)


decrypt_combo = ttk.Combobox(window, textvariable=file_path_decrypt, width=100)
decrypt_combo.pack(padx=5)
decrypt_combo.bind("<Button-1>", refresh_dropdowns)
decrypt_combo.bind("<<ComboboxSelected>>", on_decrypt_select)

tk.Button(window, text="Decryption", bg=Blue, fg=Red, command=decrypt_action, width=15).pack(anchor="w", padx=5, pady=5)

tk.Button(window, text="View Key Log", command=lambda: messagebox.showinfo("Key Log", Path("key_management.log").read_text() if Path("key_management.log").exists() else "No logs"),width=15).pack(anchor="w",padx=5,pady=0)

warn_canvas = tk.Canvas(window, width=480, height=70, bg=White)
warn_canvas.pack(pady=(5, 0))
warn_canvas.create_text(240, 35, text=(
    "⚠️ Warning: Mismanagement of encryption keys can lead to data breaches\n"
    "and loss of sensitive information. Ensure that encryption keys are\n"
    "stored and managed securely."
), fill="red", font="Arial 12 bold", anchor="center", justify="center")

# Initialize
generate_rsa_keys()
encrypt_combo.set("")
decrypt_combo.set("")
update_encrypt_combo()
encrypt_combo.bind("<Button-1>", refresh_dropdowns)
decrypt_combo.bind("<Button-1>", refresh_dropdowns)
encrypt_combo.bind("<<ComboboxSelected>>", on_encrypt_select)
window.lift()
window.attributes("-topmost", True)
window.after_idle(window.attributes, "-topmost", False)
window.focus_force()
update_decrypt_combo()


window.mainloop()
