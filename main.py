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
                    result_label.config(text=data_c)
                    save_button.config(state=NORMAL)
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
                    result_label.config(text=data_c)
                    save_button.config(state=NORMAL)
            except Exception as e:
                messagebox.showerror("Error", str(e))
        else:
            messagebox.showerror("Error", "Please select a file.")

def save_file():
    result = result_label.cget("text")
    filepath = filedialog.asksaveasfilename(defaultextension=".txt", initialfile='encrypted.txt')
    if filepath:
        with open(filepath, "wb") as f:
            f.write(result)
        result_label.config(text="File saved.")
        save_button.config(state=DISABLED)
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

result_label = ttk.Label(root, text="")
result_label.grid(row=2, column=0, columnspan=2)

save_button = ttk.Button(root, text="Save File", command=save_file, state=DISABLED)
save_button.grid(row=3, column=0, columnspan=2)

root.mainloop()
