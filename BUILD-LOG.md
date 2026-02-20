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