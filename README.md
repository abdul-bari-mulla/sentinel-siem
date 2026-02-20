# Sentinel - Automated Threat Detection Platform

> Custom SIEM built with ELK Stack for real-time security monitoring and automated threat detection

[![Status](https://img.shields.io/badge/status-in%20development-yellow)](https://github.com/YOUR_USERNAME/sentinel-siem)
[![ELK](https://img.shields.io/badge/ELK-8.11.0-blue)](https://www.elastic.co/)
[![Python](https://img.shields.io/badge/python-3.8+-green)](https://www.python.org/)

## 🎯 Project Goal

Building a production-grade SIEM (Security Information and Event Management) platform to detect and analyze cyber threats in real-time. This project demonstrates security analysis, log correlation, threat detection, and automated response capabilities.

**Target Use Case:** Portfolio project for SOC Analyst / DFIR / Threat Researcher / Security Analyst internship applications.

## 🔥 Key Features (Planned)

- ✅ Real-time log ingestion and parsing via Logstash
- ✅ 12+ automated threat detection rules
- 🚧 Behavioral anomaly detection using ML
- 🚧 Threat intelligence feed integration
- 🚧 Automated incident response workflows
- 🚧 Custom dashboards and visualizations
- 🚧 Email/Slack alerting system

## 🎯 Detection Capabilities

### Core Detections (Implemented)
1. **Brute Force Attacks** - Multiple failed authentication attempts
2. **SQL Injection** - Malicious SQL patterns in HTTP requests
3. **Port Scanning** - Sequential port connection attempts
4. **Directory Traversal** - Path traversal attempts (../)
5. **Command Injection** - Shell metacharacters in requests
6. **Cross-Site Scripting (XSS)** - Script injection attempts
7. **Credential Stuffing** - Password spray patterns
8. **Suspicious File Uploads** - Web shell detection

### Advanced Detections (Planned)
9. Application-layer DoS
10. User-Agent anomalies
11. Geographic anomalies
12. Privilege escalation attempts

## 🏗️ Architecture
```
[Log Sources]  →  [Logstash]  →  [Elasticsearch]  →  [Kibana Dashboard]
                      ↓                ↓
             [Parsing/Enrichment]      ↓
                                       ↓
                               [Detection Engine]
                                       ↓
                               [Alerts & Response]
```

### Tech Stack
- **Elasticsearch 8.11** - Log storage and search
- **Logstash 8.11** - Log parsing and enrichment
- **Kibana 8.11** - Visualization and dashboards
- **Python 3.x** - Detection engine and log generation
- **Docker** - Container orchestration

## 📊 Current Status

**Phase 1: Foundation** ✅
- [x] ELK Stack deployment
- [x] Container orchestration with Docker Compose
- [x] Basic configuration

**Phase 2: Detection (In Progress)** 🚧
- [ ] Log generation framework
- [ ] Detection engine implementation
- [ ] Rule development
- [ ] Dashboard creation

**Phase 3: Advanced Features** 📅
- [ ] Real attack simulation
- [ ] Threat intel integration
- [ ] Automated response
- [ ] Documentation & blog post

## 🚀 Quick Start

### Prerequisites
- Docker Desktop
- 4GB+ RAM available
- Python 3.8+

### Installation
```bash
# Clone the repository
git clone https://github.com/abdul-bari-mulla/sentinel-siem.git
cd sentinel-siem

# Start the ELK stack
docker compose up -d

# Verify all services are running
docker ps

# Access Kibana
# http://localhost:5601

# Access Elasticsearch
# http://localhost:9200
```

## 📈 Project Timeline

- **Week 1:** Core SIEM setup + 8 detection rules
- **Week 2:** Advanced detections + real attack simulation
- **Week 3:** Polish, documentation, demo video

## 📝 Build Log

See [BUILD-LOG.md](BUILD-LOG.md) for detailed daily progress, challenges solved, and lessons learned.

## 🤝 Contributing

This is a personal learning project, but feedback and suggestions are welcome! Feel free to open an issue.

## 📄 License

MIT License - feel free to use this project for learning purposes.

## 👨‍💻 Author

Built by Abdul Bari as a portfolio project.

**Connect:** [LinkedIn](https://www.linkedin.com/in/abdul-bari-mulla/) | [GitHub](https://github.com/abdul-bari-mulla)
