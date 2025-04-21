import hashlib
import socket
import struct
import re
import pandas as pd

def split_log(log: str):
    # Priority regex patterns (ordered for greedy matching)
    patterns = [
        r'<\*>',                                       # Special wildcard
        r'\b\d{1,3}(?:\.\d{1,3}){3}\b',                # IP addresses
        r'\b[\w\.-]+@[\w\.-]+\.\w{2,}\b',              # Email addresses
        r'\b\d{4}-\d{2}-\d{2}\b',                      # Date: YYYY-MM-DD
        r'\b\d{2}/\d{2}/\d{4}\b',                      # Date: DD/MM/YYYY
        r'\b\d{2}:\d{2}:\d{2}\b',                      # Time: HH:MM:SS
        r'[A-Za-z]+',                                  # Words (letters only)
        r'\d+',                                        # Numbers
        r'_',                                          # Underscores as standalone
        r'\S'                                          # Any non-whitespace character
    ]

    combined_pattern = '|'.join(patterns)
    tokens = re.findall(combined_pattern, log)

    return tokens



def stable_hash(value: str, mod: int, offset: int) -> int:
    h = int(hashlib.md5(value.encode()).hexdigest(), 16)
    return offset + (h % mod)


def hash_ip(ip: str) -> int:
    try:
        packed_ip = struct.unpack("!I", socket.inet_aton(ip))[0]
        return 10000 + (packed_ip % 3000)
    except Exception:
        return stable_hash(ip, 3000, 10000)

def hash_email(email: str) -> int:
    return stable_hash(email.lower(), 3000, 13000)

def hash_large_number(number_str: str) -> int:
    return stable_hash(number_str, 3000, 16000)

def hash_date(date_str: str) -> int:
    return stable_hash(date_str, 3000, 19000)

def hash_oov_word(word: str) -> int:
    return stable_hash(word.lower(), 3000, 22000)
    
def hash_unknown(token: str) -> int:
    return stable_hash(token, 3000, 25000)


def hash_token(token: str) -> tuple[str, int]:
    token = token.strip()
    if token in dictionary:
        return "vocabulary", dictionary.index(token)

    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if ip_pattern.match(token):
        return "ip", hash_ip(token)

    email_pattern = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$')
    if email_pattern.match(token):
        return "email", hash_email(token)

    date_patterns = [
        r'^\d{4}-\d{2}-\d{2}$', r'^\d{2}/\d{2}/\d{4}$',
        r'^\d{4}/\d{2}/\d{2}$', r'^\d{2}-\d{2}-\d{4}$',
        r'^\d{4}\.\d{2}\.\d{2}$'
    ]
    for pat in date_patterns:
        if re.match(pat, token):
            return "date", hash_date(token)

    if token.isdigit() and int(token) > 10000:
        return "large_number", hash_large_number(token)

    if re.match(r'^[A-Za-z]+$', token):
        return "word", hash_oov_word(token)

    return "other", hash_unknown(token)


def log_to_token_seq(log, indent=0):
    tokens = split_log(log)
    return [hash_token(t)[1] + indent for t in tokens]

def get_labels(log, template):
    label = [0] * len(log)
    j = 0
    for i in range(len(log)):
        if log[i] == template[j]:
            label[i] = 0
            j += 1
        elif template[j] == '<*>':
            if j+1 < len(template) and log[i] == template[j+1]:
                j += 2
            else:
                label[i] = 1
        else:
            print("smth wrong", log[i], template[j], log, template)
    return label

# Load dictionary from templates
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
