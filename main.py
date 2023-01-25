import base64
import string
import random
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

def generate_password():
    password = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    password_entry.delete(0, END)
    password_entry.insert(0, password)

root = Tk()
root.geometry("700x250")
root.title("Encryption/Decryption GUI")
root['background']='#cef2f5'

style = ttk.Style()
style.theme_use('clam')

password_label = ttk.Label(root, text="Enter password:")
password_label.grid(row=0, column=0)
password_label['background']='#def2f3'

password_entry = ttk.Entry(root)
password_entry.grid(row=0, column=1)

encrypt_button = ttk.Button(root, text="Encrypt File", command=encrypt_file)
encrypt_button.grid(row=1, column=0, pady=10)

decrypt_button = ttk.Button(root, text="Decrypt File", command=decrypt_file)
decrypt_button.grid(row=1, column=1, pady=10)

result_label = ttk.Label(root, text="")
result_label.grid(row=2, column=0, columnspan=2)
result_label['background']='#cef2f5'

save_button = ttk.Button(root, text="Save File", command=save_file, state=DISABLED)
save_button.grid(row=3, column=0, columnspan=2, pady=10)

generate_password_button = ttk.Button(root, text="Generate Password", command=generate_password)
generate_password_button.grid(row=2, column=0, columnspan=2, pady=10)

root.rowconfigure(0, weight=1)
root.rowconfigure(1, weight=1)
root.rowconfigure(2, weight=1)
root.rowconfigure(3, weight=1)
root.columnconfigure(0, weight=1)
root.columnconfigure(1, weight=1)

root.mainloop()