"""
Sentinel Detection Engine
Analyzes logs in Elasticsearch and detects attack patterns
"""

import requests
import json
from datetime import datetime, timedelta
from collections import defaultdict

ES_HOST = "http://localhost:9200"
INDEX_NAME = "sentinel-logs"

class DetectionEngine:
    def __init__(self):
        self.alerts = []
        
    def query_logs(self, query, size=10000):
        """Query Elasticsearch for logs"""
        url = f"{ES_HOST}/{INDEX_NAME}/_search"
        response = requests.post(url, json=query, headers={'Content-Type': 'application/json'})
        
        if response.status_code == 200:
            hits = response.json()['hits']['hits']
            return [hit['_source'] for hit in hits]
        return []
    
    def create_alert(self, rule_name, severity, description, evidence):
        """Create an alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'rule': rule_name,
            'severity': severity,
            'description': description,
            'evidence': evidence
        }
        self.alerts.append(alert)
        return alert
    
    # RULE 1: Brute Force Detection
    def detect_brute_force(self):
        """Detect multiple failed login attempts from same IP"""
        print("[*] Running Rule 1: Brute Force Detection...")
        
        # Query for failed auth (401/403 status on /login)
        query = {
            "size": 10000,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"request_path.keyword": "/login"}},
                        {"terms": {"http_status": [401, 403]}}
                    ]
                }
            }
        }
        
        logs = self.query_logs(query)
        
        # Group by IP
        ip_attempts = defaultdict(list)
        for log in logs:
            ip_attempts[log['source_ip']].append(log)
        
        # Check for IPs with 5+ failed attempts
        alerts_found = 0
        for ip, attempts in ip_attempts.items():
            if len(attempts) >= 5:
                alert = self.create_alert(
                    rule_name="Brute Force Attack",
                    severity="HIGH",
                    description=f"Detected {len(attempts)} failed login attempts from {ip}",
                    evidence={
                        'source_ip': ip,
                        'attempt_count': len(attempts),
                        'timestamps': [a['@timestamp'] for a in attempts[:5]]
                    }
                )
                alerts_found += 1
                print(f"  [!] ALERT: Brute force from {ip} ({len(attempts)} attempts)")
        
        print(f"  [+] Found {alerts_found} brute force attacks")
        return alerts_found
    
    # RULE 2: SQL Injection Detection
    def detect_sql_injection(self):
        """Detect SQL injection patterns in requests"""
        print("[*] Running Rule 2: SQL Injection Detection...")
        
        query = {
            "size": 10000,
            "query": {
                "term": {"attack_type.keyword": "sql_injection"}
            }
        }
        
        logs = self.query_logs(query)
        
        # Group by IP
        ip_attacks = defaultdict(list)
        for log in logs:
            ip_attacks[log['source_ip']].append(log)
        
        alerts_found = 0
        for ip, attacks in ip_attacks.items():
            alert = self.create_alert(
                rule_name="SQL Injection Attempt",
                severity="CRITICAL",
                description=f"SQL injection attempts detected from {ip}",
                evidence={
                    'source_ip': ip,
                    'attack_count': len(attacks),
                    'sample_paths': [a['request_path'] for a in attacks[:3]]
                }
            )
            alerts_found += 1
            print(f"  [!] ALERT: SQL injection from {ip} ({len(attacks)} attempts)")
        
        print(f"  [+] Found {alerts_found} SQL injection sources")
        return alerts_found
    
    # RULE 3: Port Scanning Detection
    def detect_port_scanning(self):
        """Detect rapid sequential requests to different paths (port scan behavior)"""
        print("[*] Running Rule 3: Port Scanning Detection...")
        
        # Query for 404s and admin path probes
        query = {
            "size": 10000,
            "query": {
                "bool": {
                    "should": [
                        {"term": {"http_status": 404}},
                        {"term": {"attack_type.keyword": "admin_probe"}}
                    ]
                }
            }
        }
        
        logs = self.query_logs(query)
        
        # Group by IP and check for multiple different paths
        ip_paths = defaultdict(set)
        ip_logs = defaultdict(list)
        
        for log in logs:
            ip = log['source_ip']
            ip_paths[ip].add(log['request_path'])
            ip_logs[ip].append(log)
        
        # Alert if IP accessed 5+ different paths
        alerts_found = 0
        for ip, paths in ip_paths.items():
            if len(paths) >= 5:
                alert = self.create_alert(
                    rule_name="Port Scanning / Path Enumeration",
                    severity="MEDIUM",
                    description=f"Detected scanning behavior from {ip} ({len(paths)} unique paths)",
                    evidence={
                        'source_ip': ip,
                        'unique_paths': len(paths),
                        'sample_paths': list(paths)[:5],
                        'request_count': len(ip_logs[ip])
                    }
                )
                alerts_found += 1
                print(f"  [!] ALERT: Port scan from {ip} ({len(paths)} paths probed)")
        
        print(f"  [+] Found {alerts_found} scanning activities")
        return alerts_found
    
    # RULE 4: Directory Traversal Detection
    def detect_directory_traversal(self):
        """Detect directory traversal attempts"""
        print("[*] Running Rule 4: Directory Traversal Detection...")
        
        query = {
            "size": 10000,
            "query": {
                "term": {"attack_type.keyword": "directory_traversal"}
            }
        }
        
        logs = self.query_logs(query)
        
        ip_attacks = defaultdict(list)
        for log in logs:
            ip_attacks[log['source_ip']].append(log)
        
        alerts_found = 0
        for ip, attacks in ip_attacks.items():
            alert = self.create_alert(
                rule_name="Directory Traversal Attempt",
                severity="HIGH",
                description=f"Directory traversal attempts from {ip}",
                evidence={
                    'source_ip': ip,
                    'attack_count': len(attacks),
                    'sample_paths': [a['request_path'] for a in attacks[:3]]
                }
            )
            alerts_found += 1
            print(f"  [!] ALERT: Directory traversal from {ip} ({len(attacks)} attempts)")
        
        print(f"  [+] Found {alerts_found} directory traversal sources")
        return alerts_found
    
    # RULE 5: Command Injection Detection
    def detect_command_injection(self):
        """Detect command injection attempts"""
        print("[*] Running Rule 5: Command Injection Detection...")
        
        query = {
            "size": 10000,
            "query": {
                "term": {"attack_type.keyword": "command_injection"}
            }
        }
        
        logs = self.query_logs(query)
        
        ip_attacks = defaultdict(list)
        for log in logs:
            ip_attacks[log['source_ip']].append(log)
        
        alerts_found = 0
        for ip, attacks in ip_attacks.items():
            alert = self.create_alert(
                rule_name="Command Injection Attempt",
                severity="CRITICAL",
                description=f"Command injection attempts from {ip}",
                evidence={
                    'source_ip': ip,
                    'attack_count': len(attacks),
                    'sample_paths': [a['request_path'] for a in attacks[:3]]
                }
            )
            alerts_found += 1
            print(f"  [!] ALERT: Command injection from {ip} ({len(attacks)} attempts)")
        
        print(f"  [+] Found {alerts_found} command injection sources")
        return alerts_found
    
    # RULE 6: XSS Detection
    def detect_xss(self):
        """Detect Cross-Site Scripting attempts"""
        print("[*] Running Rule 6: XSS Detection...")
        
        query = {
            "size": 10000,
            "query": {
                "term": {"attack_type.keyword": "xss"}
            }
        }
        
        logs = self.query_logs(query)
        
        ip_attacks = defaultdict(list)
        for log in logs:
            ip_attacks[log['source_ip']].append(log)
        
        alerts_found = 0
        for ip, attacks in ip_attacks.items():
            alert = self.create_alert(
                rule_name="Cross-Site Scripting (XSS) Attempt",
                severity="HIGH",
                description=f"XSS attempts detected from {ip}",
                evidence={
                    'source_ip': ip,
                    'attack_count': len(attacks),
                    'sample_paths': [a['request_path'] for a in attacks[:3]]
                }
            )
            alerts_found += 1
            print(f"  [!] ALERT: XSS attempt from {ip} ({len(attacks)} attempts)")
        
        print(f"  [+] Found {alerts_found} XSS attack sources")
        return alerts_found
    
    # RULE 7: Credential Stuffing Detection
    def detect_credential_stuffing(self):
        """Detect credential stuffing (multiple usernames, same IP)"""
        print("[*] Running Rule 7: Credential Stuffing Detection...")
        
        query = {
            "size": 10000,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"request_path.keyword": "/login"}},
                        {"term": {"http_status": 401}}
                    ]
                }
            }
        }
        
        logs = self.query_logs(query)
        
        # Group by IP and count unique usernames
        ip_users = defaultdict(set)
        ip_logs = defaultdict(list)
        
        for log in logs:
            ip = log['source_ip']
            user = log.get('user', '-')
            if user != '-':
                ip_users[ip].add(user)
            ip_logs[ip].append(log)
        
        # Alert if 10+ different usernames from same IP
        alerts_found = 0
        for ip, users in ip_users.items():
            if len(users) >= 10:
                alert = self.create_alert(
                    rule_name="Credential Stuffing Attack",
                    severity="CRITICAL",
                    description=f"Credential stuffing detected from {ip} ({len(users)} unique usernames)",
                    evidence={
                        'source_ip': ip,
                        'unique_usernames': len(users),
                        'attempt_count': len(ip_logs[ip])
                    }
                )
                alerts_found += 1
                print(f"  [!] ALERT: Credential stuffing from {ip} ({len(users)} usernames)")
        
        print(f"  [+] Found {alerts_found} credential stuffing attacks")
        return alerts_found
    
    # RULE 8: Application DoS Detection
    def detect_application_dos(self):
        """Detect excessive requests from single IP (application-layer DoS)"""
        print("[*] Running Rule 8: Application DoS Detection...")
        
        # Get all logs
        query = {
            "size": 10000,
            "query": {"match_all": {}}
        }
        
        logs = self.query_logs(query)
        
        # Count requests per IP
        ip_counts = defaultdict(int)
        for log in logs:
            ip_counts[log['source_ip']] += 1
        
        # Alert if IP has 50+ requests (in our dataset)
        alerts_found = 0
        for ip, count in ip_counts.items():
            if count >= 50:
                alert = self.create_alert(
                    rule_name="Application-Layer DoS",
                    severity="MEDIUM",
                    description=f"Excessive requests from {ip} ({count} requests)",
                    evidence={
                        'source_ip': ip,
                        'request_count': count
                    }
                )
                alerts_found += 1
                print(f"  [!] ALERT: Potential DoS from {ip} ({count} requests)")
        
        print(f"  [+] Found {alerts_found} potential DoS sources")
        return alerts_found
    
    def run_all_rules(self):
        """Run all detection rules"""
        print("\n" + "="*60)
        print("SENTINEL DETECTION ENGINE - STARTING ANALYSIS")
        print("="*60 + "\n")
        
        total_alerts = 0
        
        total_alerts += self.detect_brute_force()
        total_alerts += self.detect_sql_injection()
        total_alerts += self.detect_port_scanning()
        total_alerts += self.detect_directory_traversal()
        total_alerts += self.detect_command_injection()
        total_alerts += self.detect_xss()
        total_alerts += self.detect_credential_stuffing()
        total_alerts += self.detect_application_dos()
        
        print("\n" + "="*60)
        print("DETECTION SUMMARY")
        print("="*60)
        print(f"Total Alerts Generated: {total_alerts}")
        print(f"Total Rules Executed: 8")
        print("="*60)
        
        # Save alerts to file
        with open('detection_alerts.json', 'w') as f:
            json.dump(self.alerts, f, indent=2)
        
        print(f"\n[+] Alerts saved to: detection_alerts.json")
        print(f"[+] You can review {len(self.alerts)} detailed alerts in the file")

def main():
    engine = DetectionEngine()
    engine.run_all_rules()

if __name__ == "__main__":
    main()