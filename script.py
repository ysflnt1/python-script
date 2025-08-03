import os
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil
from datetime import datetime, timedelta
from binascii import hexlify


def get_chrome_datetime(chromedate):
    """Convert Chrome format timestamp to Python datetime."""
    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)


def get_encryption_key():
    """Get and decrypt the AES key from Chrome's Local State."""
    try:
        local_state_path = os.path.join(os.environ["USERPROFILE"],
                                        "AppData", "Local", "Google", "Chrome",
                                        "User Data", "Local State")
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
        encrypted_key_b64 = local_state["os_crypt"]["encrypted_key"]
        encrypted_key = base64.b64decode(encrypted_key_b64)[5:]  # Strip 'DPAPI' prefix
        decrypted_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        print(f"[DEBUG] Decrypted AES key (hex): {hexlify(decrypted_key).decode()}")
        return decrypted_key
    except Exception as e:
        print(f"[ERROR] Failed to retrieve encryption key: {e}")
        return None


def decrypt_password(encrypted_password_blob, key):
    """Decrypt Chrome encrypted password using AES-GCM."""
    try:
        if encrypted_password_blob[:3] == b'v10':
            iv = encrypted_password_blob[3:15]
            ciphertext = encrypted_password_blob[15:-16]
            tag = encrypted_password_blob[-16:]

            print(f"[DEBUG] Encrypted blob (hex): {hexlify(encrypted_password_blob).decode()}")
            print(f"[DEBUG] IV: {hexlify(iv).decode()}")
            print(f"[DEBUG] Ciphertext: {hexlify(ciphertext).decode()}")
            print(f"[DEBUG] Tag: {hexlify(tag).decode()}")

            cipher = AES.new(key, AES.MODE_GCM, iv)
            decrypted = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted.decode('utf-8')
        else:
            # Might be old DPAPI style
            return win32crypt.CryptUnprotectData(encrypted_password_blob, None, None, None, 0)[1].decode()
    except Exception as e:
        print(f"[ERROR] Failed to decrypt password: {e}")
        return "<decryption failed>"


def main():
    key = get_encryption_key()
    if not key:
        print("[FATAL] Cannot continue without decryption key.")
        return

    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                           "Google", "Chrome", "User Data", "Default", "Login Data")
    temp_copy = "ChromeLoginDataTemp.db"
    try:
        shutil.copyfile(db_path, temp_copy)
    except Exception as e:
        print(f"[ERROR] Failed to copy database file: {e}")
        return

    try:
        db = sqlite3.connect(temp_copy)
        cursor = db.cursor()
        cursor.execute("""
            SELECT origin_url, action_url, username_value, password_value, 
                   date_created, date_last_used 
            FROM logins 
            ORDER BY date_created
        """)
        rows = cursor.fetchall()
        if not rows:
            print("[INFO] No saved passwords found.")
        for row in rows:
            origin_url, action_url, username, encrypted_password, date_created, date_last_used = row
            decrypted_password = decrypt_password(encrypted_password, key)
            print("=" * 60)
            print(f"Origin URL:    {origin_url}")
            print(f"Action URL:    {action_url}")
            print(f"Username:      {username}")
            print(f"Password:      {decrypted_password}")
            print(f"Encrypted (hex): {hexlify(encrypted_password).decode()}")
            if date_created and date_created != 86400000000:
                print(f"Date Created:  {get_chrome_datetime(date_created)}")
            if date_last_used and date_last_used != 86400000000:
                print(f"Last Used:     {get_chrome_datetime(date_last_used)}")
    except Exception as e:
        print(f"[ERROR] Failed to read database: {e}")
    finally:
        try:
            cursor.close()
            db.close()
            os.remove(temp_copy)
        except Exception:
            pass


if __name__ == "__main__":
    main()
