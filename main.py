import sys
import base64
from cryptography.fernet import Fernet
from tkinter import *
from tkinter import filedialog
from tkinter import messagebox
from tkinter import ttk

def encrypt_file():
    password = password_entry.get()
    if len(password) == 0:
        messagebox.showerror("Error", "Please enter a password.")
    else:
        filepath = filedialog.askopenfilename()
        if filepath:
            try:
                ssb_b64 = base64.b64encode(password.encode())
                c = Fernet(ssb_b64)
                with open(filepath, "rb") as f:
                    data = f.read()
                    data_c = c.encrypt(data)
                    with open(filepath+'.encrypted', "wb") as f:
                        f.write(data_c)
                    result_label.config(text="File successfully encrypted.")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showerror("Error", "Please select a file.")

def decrypt_file():
    password = password_entry.get()
    if len(password) == 0:
        messagebox.showerror("Error", "Please enter a password.")
    else:
        filepath = filedialog.askopenfilename()
        if filepath:
            try:
                ssb_b64 = base64.b64encode(password.encode())
                c = Fernet(ssb_b64)
                with open(filepath, "rb") as f:
                    data = f.read()
                    data_c = c.decrypt(data)
                    with open(filepath+'.decrypted', "wb") as f:
                        f.write(data_c)
                    result_label.config(text="File successfully decrypted.")
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showerror("Error", "Please select a file.")

root = Tk()
root.title("Encryption/Decryption GUI")

password_label = ttk.Label(root, text="Enter password:")
password_label.grid(row=0, column=0)

password_entry = ttk.Entry(root)
password_entry.grid(row=0, column=1)

encrypt_button = ttk.Button(root, text="Encrypt File", command=encrypt_file)
encrypt_button.grid(row=1, column=0)

decrypt_button = ttk.Button(root, text="Decrypt File", command=decrypt_file)
decrypt_button.grid(row=1, column=1)

result_label = ttk.Label(root)
result_label.grid(row=2, columnspan=2)

root.mainloop()
