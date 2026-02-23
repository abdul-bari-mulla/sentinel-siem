"""
Log Shipper for Sentinel SIEM
Reads logs and sends them to Elasticsearch
"""

import requests
import json
from datetime import datetime
import re

ES_HOST = "http://localhost:9200"
INDEX_NAME = "web-logs"
LOG_FILE = "logs/web_access.log"

LOG_PATTERN = re.compile(
    r'(?P<ip>[\d\.]+) - (?P<user>\S+) \[(?P<timestamp>[^\]]+)\] "(?P<method>\w+) (?P<path>[^\s]+) HTTP/[\d\.]+" (?P<status>\d+) (?P<size>\d+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
)

def parse_log_line(line):
    """Parse log line"""
    match = LOG_PATTERN.match(line)
    if not match:
        return None
    
    data = match.groupdict()
    
    try:
        timestamp = datetime.strptime(data['timestamp'], "%d/%b/%Y:%H:%M:%S %z")
    except:
        timestamp = datetime.now()
    
    path = data['path']
    path_lower = path.lower()
    ua_lower = data['user_agent'].lower()
    attack_type = 'normal'
    
    # SQL Injection
    if any(p in path for p in ["'", '"']) or any(p in path_lower for p in ["union", "select", "drop", "insert", "--", "/*", "or+1=1", "or%201=1"]):
        attack_type = 'sql_injection'
    
    # XSS
    elif any(p in path_lower for p in ["<script", "javascript:", "onerror", "onload", "<iframe", "<svg", "alert(", "alert%28"]):
        attack_type = 'xss'
    
    # Directory Traversal
    elif '../' in path or '..\\'  in path or '..../' in path or 'etc/passwd' in path_lower or 'etc%2fpasswd' in path_lower or 'windows' in path_lower:
        attack_type = 'directory_traversal'
    
    # Command Injection
    elif any(p in path for p in [';', '|', '&&']) or any(p in path_lower for p in ['whoami', 'cat+', 'ls+', 'rm+', 'wget', 'curl']):
        attack_type = 'command_injection'
    
    # Suspicious File Upload
    elif 'upload' in path_lower and any(ext in path_lower for ext in ['.php', '.jsp', '.aspx', 'shell', 'backdoor', 'webshell', 'c99', 'r57']):
        attack_type = 'file_upload'
    
    # Privilege Escalation 
    elif any(p in path_lower for p in ['/admin/users', '/admin/config', '/admin/permissions', '/admin/database', '/admin/system', 'user-new.php']):
        attack_type = 'privilege_escalation'
    
    # Scanner Detection (User-Agent based)
    elif any(s in ua_lower for s in ['nikto', 'sqlmap', 'nmap', 'wpscan', 'python-requests']):
        attack_type = 'scanner_activity'
    
    # Admin Probe
    elif any(a in path_lower for a in ['/admin', '/phpmyadmin', '/wp-admin', '/administrator']):
        attack_type = 'admin_probe'
    
    doc = {
        '@timestamp': timestamp.isoformat(),
        'source_ip': data['ip'],
        'user': data['user'],
        'http_method': data['method'],
        'request_path': path,
        'http_status': int(data['status']),
        'response_size': int(data['size']),
        'referrer': data['referrer'],
        'user_agent': data['user_agent'],
        'attack_type': attack_type,
        'is_attack': attack_type != 'normal',
        'log_type': 'web_access'
    }
    
    return doc

def main():
    print("[*] Sentinel Simple Log Shipper Starting...")
    
    # Test Elasticsearch
    print(f"[*] Testing Elasticsearch at {ES_HOST}...")
    try:
        response = requests.get(ES_HOST)
        info = response.json()
        print(f"[+] Elasticsearch responding!")
        print(f"[+] Version: {info['version']['number']}")
        print(f"[+] Cluster: {info['cluster_name']}")
    except Exception as e:
        print(f"[!] ERROR: Cannot reach Elasticsearch: {e}")
        return
    
    # Read logs
    print(f"[*] Reading logs from {LOG_FILE}...")
    try:
        with open(LOG_FILE, 'r') as f:
            logs = f.readlines()
        print(f"[*] Found {len(logs)} log lines")
    except Exception as e:
        print(f"[!] ERROR reading file: {e}")
        return
    
    # Index logs
    print(f"[*] Indexing logs to '{INDEX_NAME}'...")
    
    success = 0
    errors = 0
    attacks = 0
    attack_breakdown = {}
    
    for i, line in enumerate(logs):
        doc = parse_log_line(line.strip())
        
        if doc:
            try:
                # Send to Elasticsearch
                url = f"{ES_HOST}/{INDEX_NAME}/_doc"
                response = requests.post(
                    url, 
                    json=doc, 
                    headers={'Content-Type': 'application/json'}
                )
                
                if response.status_code in [200, 201]:
                    success += 1
                    
                    if doc['is_attack']:
                        attacks += 1
                        attack_type = doc['attack_type']
                        attack_breakdown[attack_type] = attack_breakdown.get(attack_type, 0) + 1
                else:
                    errors += 1
                    if errors <= 3:
                        print(f"[!] Error response: {response.status_code}")
                
                # Progress
                if (i + 1) % 1000 == 0:
                    print(f"[*] Processed {i + 1}/{len(logs)}... ({attacks} attacks detected)")
                    
            except Exception as e:
                errors += 1
                if errors <= 3:
                    print(f"[!] Error indexing: {e}")
        else:
            errors += 1
    
    # Summary
    print("\n" + "="*60)
    print("[+] LOG INGESTION COMPLETE!")
    print("="*60)
    print(f"[+] Total logs: {len(logs)}")
    print(f"[+] Successfully indexed: {success}")
    print(f"[+] Errors: {errors}")
    print(f"[+] Normal traffic: {success - attacks}")
    print(f"[+] Attack patterns detected: {attacks}")
    print("="*60)
    
    if attack_breakdown:
        print("\n[*] Attack Type Breakdown:")
        for attack_type, count in sorted(attack_breakdown.items(), key=lambda x: x[1], reverse=True):
            print(f"    {attack_type}: {count} events")
    
    print(f"\n[+] Index name: {INDEX_NAME}")
    print("[+] View in Kibana: http://localhost:5601")
    print("[+] Next: Create index pattern in Kibana!")

if __name__ == "__main__":
    main()