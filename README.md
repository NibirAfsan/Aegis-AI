# AEGIS-AI: Autonomous Security Intelligence Framework

> **MSc Cybersecurity Project** — AI-powered penetration testing + ML-powered incident response with GenAI continuous learning.

AEGIS-AI is a closed-loop cybersecurity framework that combines offensive penetration testing with defensive threat detection and automated incident response. It scans targets, plans and executes AI-driven attacks, detects those attacks in real-time using ML, and generates professional security reports — all from a single dashboard.

---

## Features

### Offensive Engine
- **Multi-tool scanning:** Nmap, Nuclei, Gobuster, Nikto, ZAP, theHarvester
- **AI attack planning:** GenAI (Gemini/Groq) analyses scan results and plans up to 25 attack vectors
- **Autonomous exploitation:** Metasploit, SQLMap, Hydra, Nikto, ZAP, netcat
- **Evidence collection:** SHA256 chain of custody for all attack evidence
- **Professional reports:** AI-generated pentest + DFIR reports with PDF download
- **Compliance mapping:** GDPR, ISO 27001, PCI DSS, NIST framework alignment

### Defensive Engine (SOC/SIEM)
- **ML-powered detection:** CIC-IDS2017 trained model (99.61% accuracy, 2.83M samples)
- **Hybrid detection:** ML model + flow-based pattern analysis (PORT_SCAN, BRUTE_FORCE, DOS, DDOS, INFILTRATION)
- **Real-time dashboard:** Live threat counters, packet analysis, traffic monitor
- **GenAI incident response:** Automated response playbook generation

### Dynamic Learning (GenAI-in-the-loop)
- **Automatic detection logging:** Every threat classified and stored
- **GenAI auto-validation:** Gemini reviews and corrects ML classifications
- **Anomaly detection:** Flags unknown attack patterns for review
- **Retrain infrastructure:** Verified feedback data ready for model improvement
- **Self-improving system:** Each detection cycle makes the model smarter

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    AEGIS-AI DASHBOARD                    │
│  ┌──────────────────┐    ┌────────────────────────────┐ │
│  │ OFFENSIVE ENGINE  │    │  SOC DEFENSIVE MONITOR     │ │
│  │ Scan → Attack     │    │  ML Detection → GenAI      │ │
│  │ → Report          │    │  Response → Learning       │ │
│  └────────┬─────────┘    └──────────┬─────────────────┘ │
└───────────┼──────────────────────────┼──────────────────┘
            │                          │
    ┌───────▼───────┐         ┌───────▼────────┐
    │  Celery/Redis │         │  Scapy Listener │
    │  (async tasks)│         │  (packet capture)│
    └───────┬───────┘         └───────┬─────────┘
            │                          │
    ┌───────▼───────┐         ┌───────▼────────┐
    │   GenAI API   │         │   ONNX Model   │
    │ Gemini / Groq │         │  + Flow Rules   │
    └───────────────┘         └────────────────┘
```

**Tech Stack:** Django 4.2 · Celery · Redis · Scapy · ONNX Runtime · Gemini API · Docker · Python 3.11+

---

## Prerequisites

### System Requirements
- **OS:** Kali Linux (recommended) or Ubuntu 22.04+ (WSL2 on Windows works)
- **Python:** 3.11 or higher
- **Docker:** For the vulnerable lab environment
- **RAM:** 8GB minimum (16GB recommended)
- **Network:** Internet access for GenAI API calls

### Required Tools (install on Kali/Ubuntu)
```bash
# These should be pre-installed on Kali Linux
# If not, install them:
sudo apt update
sudo apt install -y nmap nikto gobuster nuclei hydra netcat-openbsd \
                    redis-server docker.io docker-compose wordlists

# Start Redis
sudo systemctl start redis-server
sudo systemctl enable redis-server

# Start Docker
sudo systemctl start docker
sudo systemctl enable docker
```

### Metasploit Framework
```bash
# Pre-installed on Kali Linux
# On Ubuntu: https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html
msfconsole --version
```

---

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/NibirAfsan/Aegis-AI.git
cd Aegis-AI
```

### 2. Create Python Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Python Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
```bash
cp .env.example .env
# Edit .env with your API keys:
nano .env
```

You need at minimum a `GEMINI_API_KEY`. Get one free at https://aistudio.google.com/apikey

### 5. Set Up the Database
```bash
python manage.py migrate
```

### 6. Start the Docker Lab (for testing)
```bash
docker-compose up -d
```

This starts:
| Container | Port | Description |
|-----------|------|-------------|
| DVWA | 8081 | Damn Vulnerable Web App |
| Juice Shop | 8082 | OWASP Juice Shop |
| Metasploitable2 | 8083 (HTTP), 2121 (FTP), 2222 (SSH), 3306 (MySQL), 5432 (PostgreSQL), 1524 (backdoor) | Intentionally vulnerable Linux |
| ZAP Proxy | 8090 | OWASP ZAP for web scanning |
| Redis | 6379 | Message broker and cache |

### 7. Verify Installation
```bash
# Check Docker containers are running
docker ps

# Check Redis
redis-cli ping    # Should return PONG

# Check ML model loads
source venv/bin/activate
python3 -c "
import os, django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'aegis_web.settings')
django.setup()
from core.ml_detector import load_model, get_model_info
load_model()
print(get_model_info())
"
```

---

## Running AEGIS-AI

You need **4 terminals** running simultaneously:

### Terminal 1 — Django Web Server
```bash
cd ~/Aegis-AI     # or wherever you cloned it
source venv/bin/activate
python manage.py runserver 0.0.0.0:8000
```

### Terminal 2 — Celery Worker (async task processing)
```bash
cd ~/Aegis-AI
source venv/bin/activate
celery -A aegis_web worker --loglevel=info
```

### Terminal 3 — Metasploit RPC (for attack execution)
```bash
msfconsole -q -x "load msgrpc Pass=aegis123 ServerPort=55553 SSL=false"
```

### Terminal 4 — SIEM Listener (for defensive monitoring)
```bash
cd ~/Aegis-AI
redis-cli -n 1 flushdb    # clear old SIEM data
./start_listener.sh
```

### Open Dashboard
Navigate to: **http://localhost:8000**

---

## Usage

### Offensive — Scanning and Attacking
1. Enter target IP/domain in the dashboard (e.g., `localhost` for lab)
2. Select scan type: LAB AUDIT, QUICK RECON, WEB AUDIT, or DEEP PENETRATION
3. Click **INITIATE MISSION** — wait for scan to complete
4. Review findings in the tabbed results panel
5. Click **EXECUTE BREACH SEQUENCE** — AI plans and executes attacks
6. Click **GENERATE REPORT** — AI writes professional pentest report
7. Click **Download PDF Report** — get the professional PDF

### Defensive — SIEM Monitoring
1. Start the listener (Terminal 4) before scanning
2. Watch the SOC Defensive Monitor panel for live threat detection
3. Threat counters show: threats detected, critical alerts, packets analysed
4. Click **GENERATE AI RESPONSE PLAYBOOK** when threats appear
5. The playbook provides specific incident response commands

### Dynamic Learning — GenAI Validation
```bash
# After running scans with listener active:

# Sync Redis alerts to training data + run GenAI validation
curl -X POST http://localhost:8000/siem/validate/ \
  -H "Content-Type: application/json" \
  -d '{"count": 20}'

# Check learning pipeline status
curl http://localhost:8000/siem/learning/ | python3 -m json.tool

# Or use the retrain script
source venv/bin/activate
python retrain_model.py
```

---

## Project Structure

```
Aegis-AI/
├── aegis_web/              # Django project settings
│   ├── settings.py         # Configuration (Celery, Redis, API keys)
│   ├── celery.py           # Celery configuration
│   └── urls.py             # Root URL configuration
├── core/                   # Core engine modules
│   ├── aegis_scanner.py    # Multi-tool scanning engine
│   ├── aegis_listener.py   # Scapy packet capture + Redis storage
│   ├── ai_engine.py        # GenAI integration (Gemini/Groq/Anthropic)
│   ├── attack_engine.py    # Autonomous attack orchestrator
│   ├── ml_detector.py      # Hybrid ML + flow-based detection
│   ├── feedback_engine.py  # Dynamic learning pipeline
│   └── tasks.py            # Celery async tasks
├── scanner_ui/             # Django web application
│   ├── models.py           # Database models
│   ├── views.py            # API endpoints + PDF generation
│   ├── urls.py             # URL routing
│   └── templates/          # Dashboard HTML
├── ml_models/              # ML model files
│   ├── aegis_ids_model.onnx       # Trained ONNX model (23MB)
│   ├── label_encoder.json         # Class labels
│   ├── scaler_params.json         # Feature scaling parameters
│   ├── model_summary.json         # Model metadata
│   ├── confusion_matrix.png       # Training evaluation
│   ├── feature_importance.png     # Feature importance chart
│   └── training_feedback.csv      # Dynamic learning data (generated)
├── evidence/               # Attack evidence (generated per scan)
├── docker-compose.yml      # Docker lab environment
├── start_listener.sh       # SIEM listener startup script
├── retrain_model.py        # Dynamic learning status + retrain
├── requirements.txt        # Python dependencies
├── .env.example            # Environment variable template
└── README.md               # This file
```

---

## ML Model Details

| Property | Value |
|----------|-------|
| Algorithm | RandomForest (100 trees, max_depth=20) |
| Dataset | CIC-IDS2017 |
| Training Samples | 2,827,876 |
| Features | 70 network flow features |
| Classes | 10 (NORMAL, PORT_SCAN, BRUTE_FORCE, DOS, DDOS, BOTNET, INFILTRATION, WEB_ATTACK, SQL_INJECTION, HEARTBLEED) |
| Accuracy | 99.61% |
| F1 Score | 0.9971 |
| Format | ONNX (cross-platform) |
| Inference Speed | 0.4ms per packet (2,736 packets/sec) |

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Dashboard |
| `/start-scan/` | POST | Start vulnerability scan |
| `/scan-status/<task_id>/` | GET | Poll scan progress |
| `/initiate-attack/` | POST | Start AI attack sequence |
| `/attack-status/<task_id>/` | GET | Poll attack progress |
| `/generate-report/<scan_id>/` | GET | Generate AI report |
| `/download-report/<scan_id>/` | GET | Download PDF report |
| `/live-traffic/` | GET | Get live packet data |
| `/siem/threats/` | GET | SIEM threat summary |
| `/siem/alerts/` | GET | Recent threat alerts |
| `/siem/playbook/` | POST | Generate response playbook |
| `/siem/validate/` | POST | GenAI auto-validation |
| `/siem/learning/` | GET | Learning pipeline status |

---

## Supported AI Providers

| Provider | Model | Usage |
|----------|-------|-------|
| **Gemini** (primary) | gemini-2.5-flash, gemini-2.5-flash-lite | Attack planning, reports, validation |
| **Groq** (fallback) | llama-3.3-70b-versatile | Free tier backup when Gemini is busy |
| **Anthropic** (optional) | Claude | Alternative provider |
| **DeepSeek** (optional) | deepseek-chat | Alternative provider |

---

## WSL2 Notes (Windows Users)

If running on Windows via WSL2:
- Install WSL2 with Kali Linux from Microsoft Store
- Docker Desktop must be installed and WSL2 integration enabled
- VS Code: install "Remote - WSL" extension to edit files
- The SIEM listener works best when scanning **real network targets** (not localhost) due to WSL2 loopback limitations
- Connect VS Code to WSL: `Ctrl+Shift+P` → "Remote-WSL: Connect to WSL"

---

## Disclaimer

This framework is designed for **authorised security assessments only**. Always obtain written permission before scanning or attacking any system. Unauthorised use is illegal. This tool was developed as part of an academic MSc Cybersecurity project.

---

## Author

**Nibiruzzaman Nibir** — MSc Computer Networking & Cybersecurity
University Project — 2026

---

## License

This project is for academic purposes. See LICENSE file for details.
