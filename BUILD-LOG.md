# SIEM Project Build Log - SENTINEL

## Day 1 - Environment Setup ✅ COMPLETE

### What I Built:
- ✅ Installed Docker Desktop on Windows 11
- ✅ Created project structure (config, logs, rules, scripts, data folders)
- ✅ Deployed ELK Stack using Docker Compose
- ✅ Fixed Kibana out-of-memory issue
- ✅ All 3 containers running successfully

### What I Learned:
- **Docker Fundamentals:**
  - Docker images vs containers
  - Docker Compose for multi-container apps
  - Container networking and volumes
  - Resource management (CPU/RAM limits)
  - Basic commands: `docker ps`, `docker logs`, `docker compose up/down`

- **ELK Stack Architecture:**
  - Elasticsearch: Search engine & data storage (port 9200)
  - Logstash: Log processing pipeline (port 5044)
  - Kibana: Visualization dashboard (port 5601)
  - How the three components communicate
  - Why each component is needed in a SIEM

### Technical Details:
- **Elasticsearch:** 512MB RAM allocation, single-node cluster
- **Kibana:** 768MB RAM allocation (fixed memory limit issue)
- **Logstash:** 256MB RAM allocation
- **Total System Impact:** ~1.5GB RAM usage

### Screenshots Taken:
- [ x ] Terminal showing `docker ps` output
- [ x ] Docker Desktop showing all containers running
- [ x ] Kibana Home Page

### Challenges Solved:
1. Docker distutils error in Ubuntu VM → Switched to Windows host
2. Kibana memory crash → Increased heap size from 256MB to 768MB
3. Understanding Logstash has no web UI (backend service only)

### Resources Used:
- Docker Documentation
- ELK Stack Official Docs
- Understanding SIEM concepts

---

## Commands Reference:

### Essential Docker Commands
```bash
# See running containers
docker ps

# See all containers (including stopped)
docker ps -a

# View logs from a container
docker logs elasticsearch
docker logs -f kibana  # -f follows logs in real-time

# Stop all containers
docker compose down

# Start all containers
docker compose up -d  # -d runs in background

# Restart a specific container
docker restart elasticsearch

# Execute command inside container
docker exec -it elasticsearch bash  # Opens shell inside container

# Remove everything (if you mess up and want fresh start)
docker compose down -v  # -v removes volumes too
```

---

### How Docker Works
Think of Docker like this:

- Image = A template/blueprint (like a .iso file for VMs)
- Container = A running instance of that image (like a running VM)
- Volume = Persistent storage (like a hard drive that survives reboots)
- Network = Virtual network connecting containers (like VMs on same subnet)

### Accessing Services
- Elasticsearch: http://localhost:9200
- Kibana: http://localhost:5601
- Logstash: Port 5044 (no web interface)

---

## Day 2 - [Actual Date] - Log Generation & Detection Engine ✅ COMPLETE

### What I Built:
- ✅ Synthetic log generator (12,000+ logs: 10k normal + 3k attacks)
- ✅ Log ingestion pipeline to Elasticsearch  
- ✅ Detection engine with 8 automated rules
- ✅ Generated 200+ security alerts
- ✅ Kibana dashboard with visualizations (attack breakdown, timeline, top IPs)

### Detection Rules Implemented (8/12):
1. **Brute Force Detection** - Multiple failed login attempts from same IP
2. **SQL Injection Detection** - Malicious SQL patterns in HTTP requests
3. **Port Scanning Detection** - Rapid sequential path enumeration
4. **Directory Traversal Detection** - Path traversal attempts (../)
5. **Command Injection Detection** - Shell metacharacters in requests
6. **XSS Detection** - Script injection attempts
7. **Credential Stuffing Detection** - Password spray patterns (multiple usernames, same IP)
8. **Application DoS Detection** - Excessive requests from single source

### What I Learned:
- **Log generation:** Creating realistic attack patterns with Python Faker
- **Regex mastery:** Parsing Apache/Nginx log formats
- **Elasticsearch operations:** Indexing, querying, aggregations via HTTP API
- **Attack pattern recognition:** Identifying SQLi, XSS, traversal signatures
- **Data analysis:** Grouping by IP, counting attempts, threshold-based detection
- **Kibana visualization:** Creating pie charts, timelines, data tables
- **KQL filtering:** Kibana Query Language for log analysis

### Technical Achievements:
- Processed 12,000+ log entries
- Detected 200+ attack instances across 8 categories
- Attack detection accuracy: ~25% attack rate (realistic ratio)
- Average detection time: <1 second per rule
- Zero false negatives on synthetic data

### Challenges Solved:
1. **Elasticsearch-py connection failure** → Used requests library with HTTP API instead
2. **Attack detection not working** → Improved regex patterns to catch URL-encoded attacks
3. **Kibana sampling only 5000 docs** → Increased sample size to show full dataset
4. **Pie chart showing 99% normal** → Re-indexed with better detection logic
5. **Log parsing edge cases** → Handled malformed timestamps and special characters

### Screenshots Taken:
- [x] `01_generate_logs.png` - Log generator output
- [x] `02_sent_to_elk.png` - Elasticsearch ingestion
- [x] `03_detection_engine_1.png` - Rules execution
- [x] `04_detection_engine_2.png` - Rules execution  
- [x] `05_kibana_discover.png` - Log exploration
- [x] `06_kibana_dashboard.png` - Complete dashboard view
- [x] `07_kibana_dashboard_filtered.png` - Attacks-only view

### Metrics:
- **Total logs:** 12,048
- **Normal traffic:** ~9,000 (75%)
- **Attack traffic:** ~3,000 (25%)
- **Alerts generated:** 200+
- **Detection rules:** 8/12 complete
- **File size:** ~1.5 MB log file
- **Processing time:** ~30 seconds for full pipeline

### Code Statistics:
- `generate_logs.py`: ~320 lines
- `send_logs_to_elk.py`: ~160 lines  
- `detection_engine.py`: ~400 lines
- **Total:** ~800 lines of Python code

---