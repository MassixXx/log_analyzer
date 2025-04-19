import hashlib
import socket
import struct

import re

def split_log(log: str):
    # Priority patterns (put <*> at the top to match it first)
    patterns = [
        r'<\*>',                                      # The <*> token
        r'\b\d{1,3}(?:\.\d{1,3}){3}\b',               # IP addresses
        r'\b[\w\.-]+@[\w\.-]+\.\w{2,}\b',             # Email addresses
        r'\b\d{4}-\d{2}-\d{2}\b',                     # Date: YYYY-MM-DD
        r'\b\d{2}/\d{2}/\d{4}\b',                     # Date: DD/MM/YYYY
        r'\b\d{2}:\d{2}:\d{2}\b',                     # Time: HH:MM:SS
        r'\b\d+\b',                                   # Numbers
        r'\b\w+\b',                                   # Alphanumeric words
        r'\S'                                         # Other non-whitespace characters
    ]

    # Compile the full regex
    combined_pattern = '|'.join(patterns)

    # Find all tokens
    tokens = re.findall(combined_pattern, log)

    return tokens

def stable_hash(value: str, mod: int, offset: int) -> int:
    """Hash a string value to a range [offset, offset+mod-1]."""
    h = int(hashlib.md5(value.encode()).hexdigest(), 16)
    return offset + (h % mod)


def hash_ip(ip: str) -> int:
    """Hash IP address into [1000–1999]"""
    try:
        packed_ip = struct.unpack("!I", socket.inet_aton(ip))[0]
        return 10000 + (packed_ip % 3000)
    except Exception:
        return stable_hash(ip, 3000, 10000)

def hash_email(email: str) -> int:
    """Hash email into [2000–2999]"""
    return stable_hash(email.lower(), 3000, 13000)

def hash_large_number(number_str: str) -> int:
    """Hash numbers > 10000 into [3000–3999]"""
    return stable_hash(number_str, 3000, 16000)

def hash_date(date_str: str) -> int:
    """Hash date string into [4000–4999]"""
    return stable_hash(date_str, 3000, 19000)

def hash_oov_word(word: str) -> int:
    """Hash unknown word into [5000–5999]"""
    return stable_hash(word.lower(), 3000, 22000)

def hash_unknown(token: str) -> int:
    """Catch-all hash into [6000–6999]"""
    return stable_hash(token, 3000, 25000)


def hash_token(token: str) -> tuple[str, int]:
    token = token.strip()
    if token in dictionary:
        return "vocabulary", dictionary.index(token)
    
    # Detect IP
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if ip_pattern.match(token):
        return "ip", hash_ip(token)

    # Detect email
    email_pattern = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$')
    if email_pattern.match(token):
        return "email", hash_email(token)

    # Detect date
    date_patterns = [
        r'^\d{4}-\d{2}-\d{2}$',           # 2025-04-08
        r'^\d{2}/\d{2}/\d{4}$',           # 08/04/2025
        r'^\d{4}/\d{2}/\d{2}$',           # 2025/04/08
        r'^\d{2}-\d{2}-\d{4}$',           # 08-04-2025
        r'^\d{4}\.\d{2}\.\d{2}$',         # 2025.04.08
    ]
    for pat in date_patterns:
        if re.match(pat, token):
            return "date", hash_date(token)

    # Detect large number
    if token.isdigit() and int(token) > 10000:
        return "large_number", hash_large_number(token)

    # Detect OOV word (contains letters and/or numbers)
    if re.match(r'^[\w\-]+$', token):
        return "word", hash_oov_word(token)

    # Fallback
    return "other", hash_unknown(token)


def log_to_token_seq(log, indent=0):
    tokens = split_log(log)
    return [hash_token(t)[1]+indent for t in tokens]


import pandas as pd

template_paths = [
    r"nulog\logs\Linux\Linux_2k.log_templates.csv",
    r"nulog\logs\Andriod\Andriod_2k.log_templates.csv",     
    r"nulog\logs\Apache\Apache_2k.log_templates.csv",
    r"nulog\logs\BGL\BGL_2k.log_templates.csv",
    r"nulog\logs\Hadoop\Hadoop_2k.log_templates.csv",
    r"nulog\logs\HDFS\HDFS_2k.log_templates.csv",
    r"nulog\logs\HealthApp\HealthApp_2k.log_templates.csv",
    r"nulog\logs\HPC\HPC_2k.log_templates.csv",
    r"nulog\logs\Mac\Mac_2k.log_templates.csv",
    r"nulog\logs\OpenSSH\OpenSSH_2k.log_templates.csv",
    r"nulog\logs\OpenStack\OpenStack_2k.log_templates.csv",
    r"nulog\logs\Proxifier\Proxifier_2k.log_templates.csv",
    r"nulog\logs\Spark\Spark_2k.log_templates.csv",
    r"nulog\logs\Thunderbird\Thunderbird_2k.log_templates.csv",
    r"nulog\logs\Windows\Windows_2k.log_templates.csv",
    r"nulog\logs\Zookeeper\Zookeeper_2k.log_templates.csv"
    ]

dictionary = set()

for path in template_paths:

    df = pd.read_csv(path)

    for log in df["EventTemplate"]:
        tokens = split_log(log)
        
        for token in tokens:
            if token != '<*>':
                dictionary.add(token)

dictionary = list(dictionary)