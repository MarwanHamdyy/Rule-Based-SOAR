# Ruled-SOAR — Rule-Based Security Orchestration, Automation & Response Engine
**Graduation Project | Python 3.11+ | Elasticsearch 8.x | Suricata | React + Vite Dashboard**

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)
![React](https://img.shields.io/badge/React-18.x-cyan.svg)

## 📌 Project Overview
**Ruled-SOAR** is a production-style, fully-deterministic SOAR engine designed to automate incident response for IoT and network environments. It ingests live Suricata IDS alerts from Elasticsearch, correlates events over time using sliding windows, applies human-readable detection rules, and automatically executes physical mitigation scripts (like isolating containers or blocking IPs via firewalls). 

**What makes this branch special:** This version (`final-SOAR-with-Dashboard`) introduces a **FastAPI backend** and a beautiful, real-time **React/Vite Dashboard**, allowing SOC analysts to view active threats, asset health, and action audit logs dynamically.

No machine-learning models are used. Every decision is explainable, traceable, and strictly rule-based.

---

## 🏗️ Architecture & How It Works
For every batch of new events, the engine performs the following pipeline:
1. **Ingestion**: Polls alerts from Elasticsearch using a checkpoint to avoid re-processing duplicate events.
2. **Normalization**: Standardizes raw ES documents into a typed internal event schema.
3. **Correlation**: Groups events per-IP using sliding time windows (30s, 1m, 5m, 15m) to track patterns.
4. **Detection**: Evaluates 8 deterministic rules (port scans, SSH brute-force, DoS floods, malware C2, etc.).
5. **Enrichment**: Queries the VirusTotal API for external threat intelligence reputation scores.
6. **Execution**: The Playbook Engine dynamically triggers scripts to block IPs, pause Docker containers, or isolate networks.
7. **Visualization**: A FastAPI service streams the action telemetry and system metrics to the React frontend.

---

## 📂 File Structure
```text
Ruled-SOAR/
├── actions/             # Action Generation, Execution Tracking, & Sanitization
├── adapters/            # External System Integrations (e.g., Docker Engine)
├── api/                 # FastAPI REST API & WebSocket handlers
├── collector/           # Ingests telemetry (ES polling, IoT logs)
├── config/              # YAML Configurations & Threshold limits
├── correlator/          # Sliding window tracking & multi-event state management
├── dashboard/           # Real-Time React + Vite frontend UI
├── enrichment/          # VirusTotal API threat intelligence
├── mappings/            # Framework mappers (MITRE ATT&CK, NIST, OWASP)
├── normalizer/          # Standardizes disparate log formats
├── playbooks/           # Playbook execution engine & lookup
├── playbook_scripts/    # Physical mitigation scripts (Endpoint, Network, IoT)
├── rules/               # Python-based detection logic
├── simulator/           # End-to-end testing & synthetic attack generator
├── utils/               # Logging, configuration loading, and state checkpoints
├── main.py              # Primary entry point for the SOAR engine
├── playbook_runner.py   # CLI tool to test playbooks manually
└── simulate.py          # CLI tool for generating synthetic attacks
```

---

## 🚀 Setup Instructions

### Prerequisites
- **Python 3.11+**
- **Node.js (v18+)** and `npm` (for the Dashboard)
- **Running ELK Stack** (Elasticsearch 8.x)
- **Suricata** shipping alerts via Filebeat to `filebeat-*`

### 1. Engine Setup
```bash
# 1. Clone the repository
git clone https://github.com/MarwanHamdyy/Rule-Based-SOAR.git
cd Rule-Based-SOAR
git checkout final-SOAR-with-Dashboard

# 2. Set up the Python virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Configure environment variables
cp .env.example .env
# Open .env and set your ES_HOST, ES_USERNAME, ES_PASSWORD, etc.

# 5. Run the core SOAR engine
python main.py
```

### 2. Dashboard Setup
The real-time visualization requires the API and React frontend to run simultaneously.
```bash
# 1. Start the FastAPI Backend (in a new terminal, ensure .venv is activated)
cd api
uvicorn main:app --reload --port 8000

# 2. Start the React Frontend (in a new terminal)
cd dashboard
npm install
npm run dev
```
Navigate to `http://localhost:5173` in your browser to view the SOC dashboard.

---

## ⚙️ What Is Expected From It? (System Capabilities)

When running properly, Ruled-SOAR will:
- **Automatically Identify Threats:** It will catch SSH brute forces, DoS floods, port scans, and malicious payloads using pre-configured thresholds in `config/thresholds.yaml`.
- **Mitigate Without Human Intervention:** Through the `playbook_scripts/`, the SOAR will automatically block attacking IP addresses at the firewall or isolate compromised Docker containers on the network.
- **Generate Audit Trails:** All actions are safely logged locally and written back to the `soar-actions-YYYY.MM.DD` index in Elasticsearch.
- **Visualize the Network:** The React dashboard will provide real-time KPI updates, threat timelines, and live incident feeds directly mapped to MITRE and OWASP frameworks.

## 🧪 Simulation Mode
Don't have a live Suricata environment yet? You can test the engine using the built-in simulator!
The simulator injects synthetic Suricata-style alert events into a dedicated index (`soar-simulation`) to validate the full pipeline.

```bash
# Generate and publish a simulated SSH brute force attack
python simulate.py run --scenario ssh_bruteforce --count 25 --rate 5

# Tell the engine to read from the simulation index
export ES_SOURCE_INDEX="soar-simulation"  # Use $env:ES_SOURCE_INDEX on Windows PowerShell

# Run the engine to process the fake attack
python main.py --mode live --once --reset-checkpoint
```

---
**Maintained by**: Marwan Hamdy
*Developed as a comprehensive Graduation Project for Advanced SOC Automation.*
