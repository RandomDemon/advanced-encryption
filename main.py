from tkinter import ttk

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
