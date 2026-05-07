# Ruled-SOAR (Antigravity) - Complete Technical Documentation

**Antigravity** (built upon the Ruled-SOAR core) is a comprehensive, deterministic, automated Security Orchestration, Automation, and Response (SOAR) engine specifically engineered for IoT self-healing defenses.

---

## 1. Executive Summary

By ingesting live Suricata Intrusion Detection System (IDS) alerts from Elasticsearch, Antigravity correlates events across sliding time windows, applies human-readable detection rules, and executes real-time mitigation playbooks.

Unlike black-box AI systems, Antigravity ensures every decision is fully deterministic, explainable, and traceable. It automatically generates structured mitigation action suggestions, executes scripts (such as isolating compromised IoT edge devices or manipulating iptables), and writes forensic data back to Elasticsearch for SOC analysts to review via Kibana and the newly integrated Real-Time React Dashboard.

**Primary Audience**: SOC Analysts, Security Engineers, and Network Administrators.

---

## 2. Project Overview

Ruled-SOAR consumes Suricata IDS alert events that Filebeat has shipped to Elasticsearch.
For every batch of new events, the engine:

1. Collects alerts from Elasticsearch using a checkpoint to avoid re-processing.
2. 2. Normalises raw ES documents into a typed internal event schema.
   3. 3. Correlates events using sliding time windows (30 s, 1 min, 5 min, 15 min).
      4. 4. Evaluates 8 deterministic detection rules across port scan, brute-force, web attacks, malware/C2, DNS anomalies, DoS, lateral movement, and generic high-risk alerts.
         5. 5. Enriches (optionally) events using the VirusTotal API.
            6. 6. Writes structured action suggestion documents to a soar-actions-YYYY.MM.DD index.
               7. 7. Executes Playbooks: Triggers automated mitigations (via SSH or EVE-NG APIs) mapping 86 attack scenarios to Python scripts.
                  8. 8. Visualises: Streams real-time alerts and IoT asset health to a dedicated FastAPI + React Dashboard.
                    
                     9. No machine-learning models are used. Every decision is explainable and traceable.
                    
                     10. ---
                    
                     11. ## 3. System Architecture
                    
                     12. The system architecture relies on a highly modular pipeline that bridges raw telemetry ingestion, stateful correlation, automated playbook execution, and real-time visualization.
                    
                     13. ```mermaid
                         graph TD
                             subaxis1(Suricata & Filebeat) -->|Raw Alerts| ES_Ingest[(Elasticsearch `filebeat-*`)]

                             ES_Ingest -->|Polling| Collector[Collector / es_collector.py]
                             Collector --> Normalizer[Event Normalizer]
                             Normalizer --> Correlator[Sliding Window Correlator]

                             Correlator --> RuleEngine[Rule Engine / 8 Deterministic Rules]
                             RuleEngine --> Enrichment[Enrichment / VirusTotal]

                             Enrichment --> ActionBuilder[Action Builder]
                             ActionBuilder --> ES_Output[(Elasticsearch `soar-actions-*`)]

                             ActionBuilder --> PlaybookRegistry[Playbook Registry]
                             PlaybookRegistry --> PlaybookExecutor[Playbook Executor]

                             PlaybookExecutor --> Mitigation[Mitigation Scripts e.g. iptables, docker network]
                             Mitigation --> EVENG((EVE-NG / IoT Assets))

                             ES_Output --> FastAPI[FastAPI Backend / REST & WebSockets]
                             FastAPI --> Dashboard[React Real-Time Dashboard]
                             ES_Output --> Kibana[Kibana Dashboards]
                         ```

                         ### Core Pipeline Components

                         1. Telemetry Ingestion (Elasticsearch 8.x)
                         2.    - Collector: Polls Elasticsearch using a durable checkpoint (checkpoint.json).
                               -    - Normalizer: Transforms raw JSON documents into a strictly typed NormalizedEvent.
                                
                                    - 2. Detection & Correlation Engine
                                      3.    - Correlator: Correlates events per source IP using sliding time windows.
                                            -    - Rule Engine: Evaluates 8 deterministic rules.
                                                 -    - Enrichment Module: Reaches out to the VirusTotal API.
                                                  
                                                      - 3. Execution & Mitigation Framework
                                                        4.    - Playbook Registry & Executor: Maps over 86 attack scenarios to functional Python response scripts.
                                                              -    - Mitigation Scripts: Includes container network isolation, iptables manipulation, credential revocation.
                                                                   -    - Target Environments: Standard Linux infrastructure and EVE-NG virtualized IoT edge devices.
                                                                    
                                                                        - 4. Real-Time SOC Dashboard
                                                                          5.    - FastAPI Backend: Serves telemetry data, KPIs, and Incident alerts via REST and WebSockets.
                                                                                -    - React Frontend: Built with Vite and vanilla CSS for real-time incident monitoring.
                                                                                 
                                                                                     - ---

                                                                                     ## 4. Prerequisites & Setup Instructions

                                                                                     ### Environment Requirements
                                                                                     - Operating System: Windows / Linux / macOS
                                                                                     - - Language: Python 3.11+, Node.js 18+
                                                                                       - - Infrastructure: ELK stack (Elasticsearch 8.x), Suricata + Filebeat
                                                                                        
                                                                                         - ### 1. Engine / Backend Setup
                                                                                        
                                                                                         - ```bash
                                                                                           cd "h:\Grad project\Ruled-SOAR"
                                                                                           python -m venv .venv
                                                                                           .venv\Scripts\activate
                                                                                           pip install -r requirements.txt

                                                                                           mkdir data logs
                                                                                           cp .env.example .env
                                                                                           ```

                                                                                           ### 2. Dashboard Setup (Frontend)

                                                                                           ```bash
                                                                                           cd dashboard
                                                                                           npm install
                                                                                           npm run build
                                                                                           ```

                                                                                           *(Note: On Windows, if npm install fails due to Execution Policies, run Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned in PowerShell as Administrator).*

                                                                                           ### 3. API Backend Setup

                                                                                           ```bash
                                                                                           cd api
                                                                                           pip install -r requirements.txt
                                                                                           ```

                                                                                           ---

                                                                                           ## 5. Environment Variables

                                                                                           Copy .env.example to .env and set the following:

                                                                                           | Variable | Default | Description |
                                                                                           |---|---|---|
                                                                                           | ES_HOST | https://localhost:9200 | Elasticsearch URL |
                                                                                           | ES_USERNAME | elastic | ES username |
                                                                                           | ES_PASSWORD | changeme | ES password |
                                                                                           | POLL_INTERVAL_SECONDS | 10 | Seconds between ES polls |
                                                                                           | ENGINE_MODE | live | live or replay |
                                                                                           | VT_ENABLED | false | Enable VirusTotal enrichment |

                                                                                           ---

                                                                                           ## 6. How Live Polling & Replay Works

                                                                                           - Live Mode: The engine reads from checkpoint.json and fetches new events every POLL_INTERVAL_SECONDS. The checkpoint ensures that if the engine crashes, it resumes without duplicates.
                                                                                           - - Replay Mode: Ignores the checkpoint and processes historical data batch by batch starting from the REPLAY_FROM date until it catches up to the present. Useful for testing rules against historical incidents.
                                                                                            
                                                                                             - ---

                                                                                             ## 7. Action Document Schema

                                                                                             Every action written to soar-actions-YYYY.MM.DD has a detailed structure containing:
                                                                                             - Identification (action_id, rule_id, attack_type)
                                                                                             - - Source & Destination IPs/Ports
                                                                                               - - Evaluation scores (priority, confidence, risk_score)
                                                                                                 - - recommended_mitigation and specific reasons for triggering
                                                                                                   - - Framework mappings (MITRE ATT&CK, NIST)
                                                                                                     - - Enrichment details (VirusTotal results if enabled)
                                                                                                      
                                                                                                       - ---
                                                                                                       
                                                                                                       ## 8. Real-Time SOC Dashboard
                                                                                                       
                                                                                                       The project includes a custom Real-Time Dashboard to augment Kibana.
                                                                                                       
                                                                                                       1. Start the FastAPI Backend:
                                                                                                       2.    ```bash
                                                                                                                cd api
                                                                                                                python main.py
                                                                                                                # Runs on http://0.0.0.0:8080
                                                                                                                ```
                                                                                                             2. Start the React Frontend:
                                                                                                             3.    ```bash
                                                                                                                      cd dashboard
                                                                                                                      npm run dev
                                                                                                                      # Runs on http://localhost:5173
                                                                                                                      ```
                                                                                                                   
                                                                                                                   The dashboard features live WebSocket updates, an Incident Feed, and a visual overview of IoT Asset Health.
                                                                                                               
                                                                                                               ---
                                                                                                         
                                                                                                         ## 9. Playbooks and Mitigation Engine
                                                                                                       
                                                                                                       Continuous Auditing: When an incident triggers a rule, the Playbook Executor automatically fires the corresponding mitigation script mapped in the mitigation_catalog.
                                                                                                       IoT Self-Healing: Mitigations applied to EVE-NG nodes or Docker containers will self-heal by isolating malicious IPs and restoring baseline networking states.
                                                                                                       
                                                                                                       ---
                                                                                                       
                                                                                                       ## 10. Simulation Mode (End-to-End Testing)
                                                                                                       
                                                                                                       Simulation Mode injects synthetic Suricata-style alert events into a dedicated soar-simulation index to test playbook execution without actual network traffic.
                                                                                                       
                                                                                                       ```bash
                                                                                                       # Publish 25 SSH bruteforce --count 25 --rate 5

                                                                                                       # Tell the engine to read from the simulation index and process
                                                                                                       $env:ES_SOURCE_INDEX = "soar-simulation"
                                                                                                       python main.py --mode live --once --reset-checkpoint
                                                                                                       ```
                                                                                                       
                                                                                                       ---
                                                                                                       
                                                                                                       ## 11. Troubleshooting
                                                                                                       
                                                                                                       1. Playbook Execution Failures: Ensure the worker running the SOAR engine has SSH/API access to target IoT nodes or EVE-NG. Check logs in ./logs/soar.log.
                                                                                                       2. 2. Dashboard Disconnected: Check if the FastAPI backend (api/main.py) crashed or review CORS headers.
                                                                                                          3. 3. Stuck Checkpoint: Delete data/checkpoint.json to force resync.
                                                                                                            
                                                                                                             4. ---
                                                                                                             5. *Built for the Graduation Project - Faculty of Computer & Information Sciences, 2025/2026.*
                                                                                                             6. .
