import subprocess
import time
import psutil
import ctypes
import sys
import os

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x00001000
PAGE_READWRITE = 0x04
MEM_RELEASE = 0x8000
INFINITE = 0xFFFFFFFF

kernel32 = ctypes.windll.kernel32

def inject_dll(pid, dll_path):
    h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_process:
        print(f"Failed to open process {pid}")
        return False

    dll_path_bytes = dll_path.encode('utf-8')
    arg_address = kernel32.VirtualAllocEx(h_process, 0, len(dll_path_bytes) + 1, MEM_COMMIT, PAGE_READWRITE)
    if not arg_address:
        print("VirtualAllocEx failed")
        kernel32.CloseHandle(h_process)
        return False

    written = ctypes.c_int(0)
    if not kernel32.WriteProcessMemory(h_process, arg_address, dll_path_bytes, len(dll_path_bytes) + 1, ctypes.byref(written)):
        print("WriteProcessMemory failed")
        kernel32.VirtualFreeEx(h_process, arg_address, 0, MEM_RELEASE)
        kernel32.CloseHandle(h_process)
        return False

    h_kernel32 = kernel32.GetModuleHandleA(b"kernel32.dll")
    load_library_addr = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")
    if not load_library_addr:
        print("GetProcAddress failed")
        kernel32.VirtualFreeEx(h_process, arg_address, 0, MEM_RELEASE)
        kernel32.CloseHandle(h_process)
        return False

    thread_id = ctypes.c_ulong(0)
    h_thread = kernel32.CreateRemoteThread(h_process, None, 0, load_library_addr, arg_address, 0, ctypes.byref(thread_id))
    if not h_thread:
        print("CreateRemoteThread failed")
        kernel32.VirtualFreeEx(h_process, arg_address, 0, MEM_RELEASE)
        kernel32.CloseHandle(h_process)
        return False

    kernel32.WaitForSingleObject(h_thread, INFINITE)
    kernel32.VirtualFreeEx(h_process, arg_address, 0, MEM_RELEASE)
    kernel32.CloseHandle(h_thread)
    kernel32.CloseHandle(h_process)

    print(f"Injected DLL into process {pid}")
    return True

def find_chrome_path():
    # Common Chrome install locations
    common_paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
    ]
    for path in common_paths:
        if os.path.isfile(path):
            return path

    # Try to find chrome in PATH environment variable
    from shutil import which
    path = which("chrome.exe")
    if path:
        return path

    return None

def launch_chrome_get_pid(chrome_path):
    before_pids = set(p.pid for p in psutil.process_iter(['name']) if p.info['name'] == 'chrome.exe')
    proc = subprocess.Popen([chrome_path])
    time.sleep(3)
    after_pids = set(p.pid for p in psutil.process_iter(['name']) if p.info['name'] == 'chrome.exe')
    new_pids = after_pids - before_pids

    if not new_pids:
        print("No new Chrome process found")
        return None

    pid = min(new_pids, key=lambda x: abs(x - proc.pid))
    return pid

if __name__ == "__main__":
    chrome_path = find_chrome_path()
    if not chrome_path:
        print("Chrome executable not found on system.")
        sys.exit(1)

    dll_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bypass_hook.dll")
    if not os.path.isfile(dll_path):
        print(f"DLL not found at: {dll_path}")
        sys.exit(1)

    pid = launch_chrome_get_pid(chrome_path)
    if pid is None:
        print("Failed to launch Chrome or find its process.")
        sys.exit(1)

    print(f"Launched Chrome with PID: {pid}")

    if not inject_dll(pid, dll_path):
        print("DLL injection failed.")
        sys.exit(1)

    print("Done.")
