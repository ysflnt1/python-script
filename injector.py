import subprocess
import time
import psutil
import ctypes
import sys
import os
from shutil import which

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x00001000
PAGE_READWRITE = 0x04
MEM_RELEASE = 0x8000
INFINITE = 0xFFFFFFFF

kernel32 = ctypes.windll.kernel32

def inject_dll(pid, dll_path):
    print(f"[+] Opening process {pid}...")
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        err = ctypes.GetLastError()
        print(f"[!] Failed to open process {pid}, error code: {err}")
        return False

    dll_path_bytes = dll_path.encode('utf-8')
    print(f"[+] Allocating memory in target process for DLL path...")
    arg_address = kernel32.VirtualAllocEx(h_process, 0, len(dll_path_bytes) + 1, MEM_COMMIT, PAGE_READWRITE)
    if not arg_address:
        err = ctypes.GetLastError()
        print(f"[!] VirtualAllocEx failed, error code: {err}")
        kernel32.CloseHandle(h_process)
        return False

    print(f"[+] Writing DLL path into target process memory...")
    written = ctypes.c_size_t(0)
    if not kernel32.WriteProcessMemory(h_process, arg_address, dll_path_bytes, len(dll_path_bytes) + 1, ctypes.byref(written)):
        err = ctypes.GetLastError()
        print(f"[!] WriteProcessMemory failed, error code: {err}")
        kernel32.VirtualFreeEx(h_process, arg_address, 0, MEM_RELEASE)
        kernel32.CloseHandle(h_process)
        return False
    print(f"[+] Wrote {written.value} bytes.")

    print("[+] Getting address of LoadLibraryA...")
    h_kernel32 = kernel32.GetModuleHandleA(b"kernel32.dll")
    if not h_kernel32:
        err = ctypes.GetLastError()
        print(f"[!] GetModuleHandleA failed, error code: {err}")
        kernel32.VirtualFreeEx(h_process, arg_address, 0, MEM_RELEASE)
        kernel32.CloseHandle(h_process)
        return False

    load_library_addr = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")
    if not load_library_addr:
        err = ctypes.GetLastError()
        print(f"[!] GetProcAddress failed, error code: {err}")
        kernel32.VirtualFreeEx(h_process, arg_address, 0, MEM_RELEASE)
        kernel32.CloseHandle(h_process)
        return False

    print("[+] Creating remote thread to load the DLL...")
    thread_id = ctypes.c_ulong(0)
    h_thread = kernel32.CreateRemoteThread(h_process, None, 0, load_library_addr, arg_address, 0, ctypes.byref(thread_id))
    if not h_thread:
        err = ctypes.GetLastError()
        print(f"[!] CreateRemoteThread failed, error code: {err}")
        kernel32.VirtualFreeEx(h_process, arg_address, 0, MEM_RELEASE)
        kernel32.CloseHandle(h_process)
        return False

    print("[+] Waiting for remote thread to finish...")
    kernel32.WaitForSingleObject(h_thread, INFINITE)

    print("[+] Cleaning up...")
    kernel32.VirtualFreeEx(h_process, arg_address, 0, MEM_RELEASE)
    kernel32.CloseHandle(h_thread)
    kernel32.CloseHandle(h_process)

    print(f"[+] DLL injected successfully into process {pid}.")
    return True

def find_chrome_path():
    common_paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
    ]
    for path in common_paths:
        if os.path.isfile(path):
            print(f"[+] Found Chrome at: {path}")
            return path

    path = which("chrome.exe")
    if path:
        print(f"[+] Found Chrome in PATH at: {path}")
        return path

    print("[!] Chrome executable not found.")
    return None

def launch_chrome_get_pid(chrome_path):
    print("[+] Collecting Chrome processes before launch...")
    before_pids = set(p.pid for p in psutil.process_iter(['name']) if p.info['name'] == 'chrome.exe')

    print("[+] Launching Chrome without sandbox...")
    proc = subprocess.Popen([chrome_path, "--no-sandbox"])

    print("[+] Waiting for Chrome to start...")
    time.sleep(3)  # Wait for the process to initialize

    print("[+] Collecting Chrome processes after launch...")
    after_pids = set(p.pid for p in psutil.process_iter(['name']) if p.info['name'] == 'chrome.exe')

    new_pids = after_pids - before_pids
    if not new_pids:
        print("[!] No new Chrome process found.")
        return None

    pid = min(new_pids, key=lambda x: abs(x - proc.pid))
    print(f"[+] New Chrome process PID detected: {pid}")
    return pid

if __name__ == "__main__":
    chrome_path = find_chrome_path()
    if not chrome_path:
        sys.exit(1)

    dll_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bypass_hook.dll")
    if not os.path.isfile(dll_path):
        print(f"[!] DLL not found at: {dll_path}")
        sys.exit(1)

    pid = launch_chrome_get_pid(chrome_path)
    if pid is None:
        print("[!] Failed to launch Chrome or find its process.")
        sys.exit(1)

    print(f"[+] Launched Chrome with PID: {pid}")

    if not inject_dll(pid, dll_path):
        print("[!] DLL injection failed.")
        sys.exit(1)

    print("[+] Done.")
