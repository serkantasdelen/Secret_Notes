from tkinter import *
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad
import os

# Derive the AES key from the master key using PBKDF2
def derive_key(master_key, salt):
    return PBKDF2(master_key, salt, dkLen=32)  # 32 bytes = 256 bits

# Encryption function
def encrypt(key, data):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))
    return ciphertext

# Save and encrypt
def save_encrypt():
    title = entry.get()
    secret = text1.get("1.0", "end-1c")
    master_key = entry2.get()
    salt = os.urandom(16)  # Generate a random salt for key derivation

    # Derive the AES key from the master key
    derived_key = derive_key(master_key.encode(), salt)

    # Encryption
    encrypted_secret = encrypt(derived_key, secret)

    # File name
    filename = title + ".txt"

    # Write the encrypted data and salt to the file
    with open(filename, "wb") as file:
        file.write(salt)
        file.write(encrypted_secret)

    messagebox.showinfo("Success", "Secret note has been saved and encrypted.")

window = Tk()
window.title("Secret Notes")
window.minsize(width=300, height=300)
window.config(bg="white")

label = Label(text="Enter Your Title")
label.config(bg="white")
label.config(fg="black")
label.pack()

entry = Entry(width=20)
entry.pack()

label2 = Label(text="Enter Your Secret")
label2.config(bg="white")
label2.config(fg="black")
label2.pack()

text1 = Text(width=20, height=10)
text1.pack()

label3 = Label(text="Enter Master Key")
label3.config(bg="white")
label3.config(fg="black")
label3.pack()

entry2 = Entry(width=20)
entry2.pack()

save_encrypt = Button(text="Save Encrypt", command=save_encrypt)
save_encrypt.pack()

# Decrypt function
def decrypt(key, ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(ciphertext)
    return decrypted_data.rstrip(b'\0').decode()  # Remove padding and decode

# Decrypt and show
def show_decrypted():
    ciphertext = text1.get("1.0", "end-1c").encode()  # Convert to byte string
    master_key = entry2.get()
    salt = ciphertext[:16]  # Extract the salt from the ciphertext

    # Derive the AES key from the master key
    derived_key = derive_key(master_key.encode(), salt)

    # Decrypt the ciphertext
    decrypted_secret = decrypt(derived_key, ciphertext[16:])

    # Show the decrypted secret
    messagebox.showinfo("Decrypted Secret", decrypted_secret)

# Create the "Decrypt" button
decrypt_button = Button(text="Decrypt", command=show_decrypted)
decrypt_button.pack()

window.mainloop()
