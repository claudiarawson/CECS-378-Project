import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter import filedialog
import time
import os
import random

class MockInstaller:
    def __init__(self, root):
        self.root = root
        self.root.title("Lockdown Browser Installer")
        self.root.geometry("600x400")
        self.root.resizable(False, False)

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
        self.frames = [self.create_welcome_frame(), self.create_license_frame(),
                       self.create_path_selection_frame(), self.create_installation_frame(), self.create_completion_frame()]
        self.current_frame = 0

        # Show the first frame
        self.show_frame(0)

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
        """Create the license agreement screen."""
        frame = tk.Frame(self.root)
        tk.Label(frame, text="License Agreement", font=("Arial", 16, "bold")).pack(pady=20)

        license_text = tk.Text(frame, wrap="word", width=70, height=10, padx=10, pady=10)
        license_text.insert("1.0", "By clicking 'Accept,' you agree to the terms and conditions of this mock license.")
        license_text.config(state="disabled")
        license_text.pack(pady=10)

        button_frame = tk.Frame(frame)
        button_frame.pack(side="bottom", fill="x", pady=10, padx=10)
        ttk.Button(button_frame, text="Decline", command=self.root.destroy).pack(side="right", padx=5)
        ttk.Button(button_frame, text="Accept", command=lambda: self.show_frame(2)).pack(side="right", padx=5)

        return frame

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

        # Button Frame for Bottom-Right Buttons
        button_frame = tk.Frame(frame)
        button_frame.pack(side="bottom", fill="x", pady=10, padx=10)

        # Cancel and Next Buttons
        ttk.Button(button_frame, text="Cancel", command=self.root.destroy).pack(side="right", padx=5)
        ttk.Button(button_frame, text="Next", command=self.start_installation_from_path).pack(side="right", padx=5)

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
        tk.Label(frame, text="Installing Lockdown Browser", font=("Arial", 16, "bold")).pack(pady=20)
        tk.Label(frame, text="Click 'Install' to begin the installation.", font=("Arial", 12)).pack(pady=10)

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
        self.install_button = ttk.Button(button_frame, text="Install", command=self.start_installation)
        self.install_button.pack(side="right", padx=5)

        return frame

    def start_installation(self):
        """Simulate installation with a progress bar and random file installation logs."""
        self.install_button.config(state="disabled")
        total_files = len(self.files_to_install)
        
        for i in range(101):
            time.sleep(0.05)  # Simulate work
            self.progress["value"] = i

            # Simulate file installations randomly
            if self.files_to_install and i % (100 // total_files) == 0:
                file_to_install = random.choice(self.files_to_install)
                self.install_log.insert(tk.END, f"Installing {file_to_install}")
                self.files_to_install.remove(file_to_install)

            self.root.update_idletasks()

        messagebox.showinfo("Installation Complete", f"Lockdown Browser has been successfully installed to {self.install_path}!")
        self.show_frame(4)


    def create_completion_frame(self):
        """Create the completion screen."""
        frame = tk.Frame(self.root)
        tk.Label(frame, text="Installation Complete", font=("Arial", 16, "bold")).pack(pady=20)
        tk.Label(frame, text="Thank you for installing Lockdown Browser.", font=("Arial", 12)).pack(pady=10)

        button_frame = tk.Frame(frame)
        button_frame.pack(side="bottom", fill="x", pady=10, padx=10)
        ttk.Button(button_frame, text="Finish", command=self.root.destroy).pack(side="right", padx=5)

        return frame


# Main Application
if __name__ == "__main__":
    root = tk.Tk()
    app = MockInstaller(root)
    root.mainloop()
