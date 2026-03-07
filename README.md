# Ruled-SOAR — Rule-Based Security Orchestration, Automation & Response Engine

> **Graduation Project** | Python 3.11+ | Elasticsearch 8.x | Suricata + Filebeat

A production-style, fully-deterministic SOAR engine that ingests live Suricata alerts
from Elasticsearch, correlates events over time, applies human-readable detection rules,
and writes structured action suggestions back to Elasticsearch for Kibana dashboards.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture Diagram](#architecture-diagram)
3. [Folder Structure](#folder-structure)
4. [Setup Instructions](#setup-instructions)
5. [Environment Variables](#environment-variables)
6. [How Live Polling Works](#how-live-polling-works)
7. [How Replay Mode Works](#how-replay-mode-works)
8. [How to Add New Rules](#how-to-add-new-rules)
9. [Action Document Schema](#action-document-schema)
10. [Kibana Dashboard Guide](#kibana-dashboard-guide)
11. [VirusTotal Integration](#virustotal-integration)
12. [Module Reference](#module-reference)
13. [Running Tests](#running-tests)
14. [Limitations & Future Work](#limitations--future-work)

---

## Project Overview

Ruled-SOAR consumes Suricata IDS alert events that Filebeat has shipped to Elasticsearch.
For every batch of new events, the engine:

1. **Collects** alerts from Elasticsearch using a checkpoint to avoid re-processing.
2. **Normalises** raw ES documents into a typed internal event schema.
3. **Correlates** events using sliding time windows (30 s, 1 min, 5 min, 15 min).
4. **Evaluates** 8 deterministic detection rules across port scan, brute-force, web attacks,
   malware/C2, DNS anomalies, DoS, lateral movement, and generic high-risk alerts.
5. **Enriches** (optionally) events using the VirusTotal API.
6. **Writes** structured action suggestion documents to a `soar-actions-YYYY.MM.DD` index.

No machine-learning models are used. Every decision is explainable and traceable.

---

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                     RULED-SOAR ENGINE                               │
│                                                                     │
│  Elasticsearch (source)           Elasticsearch (target)            │
│   filebeat-*                       soar-actions-YYYY.MM.DD          │
│       │                                    ▲                        │
│       │                                    │                        │
│  ┌────▼────────┐   ┌──────────┐   ┌────────┴─────┐                 │
│  │  Collector  │──▶│Normalizer│──▶│ Action Writer │                 │
│  │(es_collector│   │(event_   │   │ (es_writer)   │                 │
│  │  .py)       │   │normalizer│   └──────▲────────┘                 │
│  │checkpoint   │   │.py)      │          │                          │
│  └─────────────┘   └────┬─────┘   ┌──────┴───────┐                 │
│                         │         │ActionBuilder  │                 │
│                         ▼         │(action_builder│                 │
│                  ┌─────────────┐  │.py)           │                 │
│                  │ Correlator  │  └──────▲────────┘                 │
│                  │(sliding_    │         │      ▲                   │
│                  │ window +    │  ┌──────┴──┐  ┌┴──────────┐       │
│                  │state_manager│  │Rule     │  │Enrichment │       │
│                  │.py)         │  │Engine   │  │(VirusTotal│       │
│                  └──────┬──────┘  │(8 rules)│  │optional)  │       │
│                         │         └──────────┘  └───────────┘       │
│                         └─────────────▲                             │
│                                       │ stats query                 │
│                              ┌────────┴──────────┐                  │
│                              │  Framework Mapper  │                  │
│                              │ (MITRE/OWASP/NIST) │                  │
│                              └───────────────────┘                  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Folder Structure

```
Ruled-SOAR/
├── main.py                      # Entry point
├── requirements.txt             # Python dependencies
├── Makefile                     # Convenience targets
├── .env.example                 # Environment template
│
├── config/
│   ├── settings.yaml            # Main configuration
│   ├── thresholds.yaml          # Rule detection thresholds
│   └── rules/                   # (future: per-rule YAML overrides)
│
├── collector/
│   └── es_collector.py          # Poll ES, maintain checkpoint
│
├── normalizer/
│   └── event_normalizer.py      # Raw ES doc → NormalizedEvent
│
├── correlator/
│   ├── sliding_window.py        # Per-IP time-window data structure
│   └── state_manager.py         # Multi-window correlation state
│
├── rules/
│   ├── base_rule.py             # Abstract rule + RuleMatch dataclass
│   ├── rule_engine.py           # Dispatches all registered rules
│   ├── port_scan.py             # SOAR-001
│   ├── ssh_bruteforce.py        # SOAR-002
│   ├── web_attack.py            # SOAR-003
│   ├── malware_c2.py            # SOAR-004
│   ├── dns_suspicious.py        # SOAR-005
│   ├── dos_flood.py             # SOAR-006
│   ├── lateral_movement.py      # SOAR-007
│   └── generic_high_risk.py     # SOAR-008
│
├── enrichment/
│   └── virustotal.py            # Optional VT API (disabled by default)
│
├── actions/
│   ├── action_builder.py        # Assemble SOAR action document
│   └── es_writer.py             # Index to ES + deduplication
│
├── mappings/
│   ├── framework_mapper.py      # Lookup MITRE/OWASP/NIST refs
│   ├── mitre.json               # MITRE ATT&CK per attack type
│   ├── owasp.json               # OWASP Top-10 refs
│   └── nist.json                # NIST control refs
│
├── utils/
│   ├── logger.py                # Colour logging + rotation
│   ├── config_loader.py         # YAML + .env loader
│   └── checkpoint.py            # Persist last-processed timestamp
│
└── tests/
    ├── sample_events.py         # 10 mock Suricata events
    ├── test_normalizer.py
    ├── test_correlator.py
    ├── test_rules.py
    └── test_action_builder.py
```

---

## Setup Instructions

### Prerequisites

- Python 3.11+
- Running ELK stack (Elasticsearch 8.x)
- Suricata shipping alerts via Filebeat to `filebeat-*`

### Install

```bash
# 1. Clone / navigate to project
cd "g:/Grad project/Ruled-SOAR"

# 2. Create virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Linux/macOS

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
copy .env.example .env
# Edit .env with your ES credentials

# 5. Create required directories
mkdir data logs

# 6. Run the engine (live mode)
python main.py
```

### Using the Makefile (on Linux/macOS or with make for Windows)

```bash
make install      # pip install -r requirements.txt
make setup        # copies .env and creates dirs
make run          # live mode
make run-replay   # replay mode
make run-once     # single poll + exit
make test         # run all unit tests
make test-cov     # tests with coverage report
```

---

## Environment Variables

Copy `.env.example` to `.env` and set the following:

| Variable | Default | Description |
|---|---|---|
| `ES_HOST` | `https://localhost:9200` | Elasticsearch URL |
| `ES_USERNAME` | `elastic` | ES username |
| `ES_PASSWORD` | `changeme` | ES password |
| `ES_API_KEY` | _(empty)_ | Base64 API key (overrides user/pass) |
| `ES_VERIFY_CERTS` | `false` | Verify TLS certs (set `true` in prod) |
| `ES_SOURCE_INDEX` | `filebeat-*` | Source index pattern |
| `ES_TARGET_INDEX_PREFIX` | `soar-actions` | Action index prefix |
| `POLL_INTERVAL_SECONDS` | `10` | Seconds between ES polls |
| `ENGINE_MODE` | `live` | `live` or `replay` |
| `CHECKPOINT_FILE` | `./data/checkpoint.json` | Checkpoint persistence path |
| `REPLAY_FROM` | `2024-01-01T00:00:00Z` | Start time for replay mode |
| `VT_ENABLED` | `false` | Enable VirusTotal enrichment |
| `VT_API_KEY` | _(empty)_ | VirusTotal API key |
| `LOG_LEVEL` | `INFO` | Logging verbosity |
| `LOG_FILE` | `./logs/soar.log` | Rotating log file path |

---

## How Live Polling Works

```
1. Engine starts → loads checkpoint.json (last processed @timestamp)
2. Every POLL_INTERVAL_SECONDS:
   a. Query ES: event.type=alert AND @timestamp > last_checkpoint
   b. Sort results by @timestamp ASC (oldest first)
   c. Normalise each doc → NormalizedEvent
   d. Ingest into sliding windows (correlator)
   e. Query per-IP stats from all windows
   f. Evaluate all 8 rules
   g. Build + write action docs for matches
   h. Save newest @timestamp as new checkpoint
3. Sleep → repeat
```

**Checkpoint durability:** The checkpoint is saved to disk after every successful batch.
If the engine crashes and restarts, it resumes from the last saved checkpoint with no duplicates.

---

## How Replay Mode Works

Set in `.env`:
```ini
ENGINE_MODE=replay
REPLAY_FROM=2024-01-01T00:00:00Z
```

Or use the CLI flag:
```bash
python main.py --mode replay
```

In replay mode:
- The engine ignores any saved checkpoint.
- It starts querying events from `REPLAY_FROM`.
- It processes historical data batch by batch until it catches up to present.
- The engine then continues in live mode.

This is useful for:
- Testing detection rules against historical incidents.
- Reprocessing logs after adding new rules.

---

## How to Add New Rules

Adding a new rule requires **3 steps**:

### Step 1 — Create a rule module

```python
# rules/my_new_rule.py
from rules.base_rule import BaseRule, RuleMatch
from correlator.sliding_window import WindowStats
from normalizer.event_normalizer import NormalizedEvent

class MyNewRule(BaseRule):
    RULE_ID = "SOAR-009"
    ATTACK_TYPE = "my_attack_type"

    def evaluate(self, event, stats, config):
        cfg = config.get("my_attack_type", {})
        w = stats.get("medium")
        if w.event_count < cfg.get("threshold", 10):
            return None
        return RuleMatch(
            rule_id=self.RULE_ID,
            attack_type=self.ATTACK_TYPE,
            priority="HIGH",
            confidence=0.80,
            recommended_mitigation="Investigate and block.",
            reasons=[f"Detected {w.event_count} events."],
        )
```

### Step 2 — Register in the rule engine

```python
# rules/rule_engine.py
from rules.my_new_rule import MyNewRule

RULES: list[BaseRule] = [
    ...
    MyNewRule(),   # Add before GenericHighRiskRule
    GenericHighRiskRule(),
]
```

### Step 3 — Add thresholds to `config/thresholds.yaml`

```yaml
rules:
  my_attack_type:
    threshold: 10
    confidence: 0.80
    priority: "HIGH"
```

**Done.** No other files need to change.

---

## Action Document Schema

Every action written to `soar-actions-YYYY.MM.DD` has this structure:

```json
{
  "@timestamp": "2024-06-01T10:05:00.123456+00:00",
  "action_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "rule_id": "SOAR-002",
  "attack_type": "ssh_bruteforce",
  "source_ip": "203.0.113.10",
  "source_port": 4444,
  "destination_ip": "10.0.0.20",
  "destination_port": 22,
  "protocol": "tcp",
  "priority": "HIGH",
  "confidence": 0.9,
  "risk_score": 80.0,
  "recommended_mitigation": "Immediately block the source IP via firewall ACL...",
  "reasons": [
    "SSH alert repeated 10 times (threshold: 8) in 30s from 203.0.113.10 → port 22.",
    "Matched signature: 'ET SCAN SSH BruteForce Tool with fake PUTTY version'.",
    "Event risk_score: 80.0."
  ],
  "original_event": {
    "timestamp": "2024-06-01T10:01:00.000Z",
    "signature": "ET SCAN SSH BruteForce Tool with fake PUTTY version",
    "signature_id": 2001219,
    "category": "Attempted Administrator Privilege Gain",
    "severity": 1,
    "hostname": "ids-sensor-01",
    "es_index": "filebeat-8.12.0-2024.06.01",
    "es_id": "evt-002"
  },
  "framework_mapping": {
    "mitre_tactic": "Credential Access",
    "mitre_technique": "T1110 - Brute Force",
    "nist_ref": "NIST SP 800-63B - Digital Identity Guidelines"
  },
  "enrichment": {
    "provider": "virustotal",
    "malicious": 15,
    "suspicious": 2,
    "reputation": -20,
    "country": "CN",
    "as_owner": "EXAMPLE-AS",
    "tags": ["scanner", "brute"]
  }
}
```

---

## Kibana Dashboard Guide

### 1. Create an Index Pattern

In Kibana → **Stack Management → Index Patterns**:
- Pattern: `soar-actions-*`
- Time field: `@timestamp`

### 2. Key Visualisations

| Visualisation | Type | X-axis | Y-axis / Bucket |
|---|---|---|---|
| Actions over time | Line chart | `@timestamp` | Count |
| Top source IPs | Horizontal bar | Count | `source_ip` keyword |
| Attack type distribution | Pie / Donut | Count | `attack_type` keyword |
| Priority breakdown | Vertical bar | `priority` keyword | Count |
| High-priority actions table | Data table | Latest actions | All fields |

### 3. Sample Kibana Saved Queries

**All CRITICAL actions in last 24h:**
```
priority: "CRITICAL" AND @timestamp >= now-24h
```

**SSH brute force actions:**
```
attack_type: "ssh_bruteforce"
```

**Actions by source IP (replace X.X.X.X):**
```
source_ip: "X.X.X.X"
```

**High-confidence actions:**
```
confidence >= 0.85
```

### 4. Recommended Dashboard Panels

1. **Metric**: Total actions today
2. **TSVB / Line**: Actions per hour (last 7 days)
3. **Top 10 Source IPs**: Data table with count and last seen
4. **Attack Types**: Pie chart
5. **Priority over time**: Stacked bar chart
6. **Latest 20 actions**: Table with all key fields

---

## VirusTotal Integration

To enable VirusTotal enrichment:

```ini
# .env
VT_ENABLED=true
VT_API_KEY=your_actual_virustotal_api_key
VT_CACHE_TTL=3600
```

When enabled, the engine will:
- Look up the **source IP** of each triggered event on VirusTotal.
- Cache results for `VT_CACHE_TTL` seconds to conserve API quota.
- Attach an `enrichment` block to the action document.
- Continue normally if VirusTotal is unreachable (non-blocking).

The free VirusTotal API allows **4 lookups/minute**.
Consider setting `VT_CACHE_TTL=86400` (24h) to conserve quota.

---

## Module Reference

| Module | Purpose |
|---|---|
| `collector/es_collector.py` | Poll ES, maintain checkpoint, support live/replay |
| `normalizer/event_normalizer.py` | Convert raw ES docs to `NormalizedEvent` dataclass |
| `correlator/sliding_window.py` | Thread-safe per-IP event ring buffer with auto-expiry |
| `correlator/state_manager.py` | Multi-window correlation state, aggregated stats |
| `rules/base_rule.py` | Abstract rule + `RuleMatch` output schema |
| `rules/rule_engine.py` | Registers and dispatches all 8 rules |
| `rules/port_scan.py` | SOAR-001: unique dst port count threshold |
| `rules/ssh_bruteforce.py` | SOAR-002: SSH repetition + port 22 |
| `rules/web_attack.py` | SOAR-003: HTTP attack signatures |
| `rules/malware_c2.py` | SOAR-004: malware sigs + high risk_score |
| `rules/dns_suspicious.py` | SOAR-005: DNS port 53 anomalies |
| `rules/dos_flood.py` | SOAR-006: volumetric alert floods |
| `rules/lateral_movement.py` | SOAR-007: unique dst host spread |
| `rules/generic_high_risk.py` | SOAR-008: severity ≤ 2 or risk_score ≥ 70 |
| `enrichment/virustotal.py` | Optional VT IP/domain lookup with in-memory cache |
| `actions/action_builder.py` | Assembles structured SOAR action document |
| `actions/es_writer.py` | Indexes action to ES with deduplication |
| `mappings/framework_mapper.py` | Loads MITRE/OWASP/NIST JSON references |
| `utils/logger.py` | Rotating colour-coded logging |
| `utils/config_loader.py` | Reads YAML + resolves `${ENV_VAR:default}` |
| `utils/checkpoint.py` | Reads/writes JSON checkpoint file |

---

## Running Tests

```bash
# Activate your virtual environment first
.venv\Scripts\activate

# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ -v --cov=. --cov-report=term-missing

# Run a single test file
pytest tests/test_rules.py -v
```

All tests are fully offline — no Elasticsearch or network access required.
Sample events in `tests/sample_events.py` mock real Filebeat-shipped documents.

---

## Limitations & Future Work

### Current Limitations

- **In-memory correlation only**: Restarting the engine clears all sliding window state.
  Ongoing correlations (e.g., a 15-minute window mid-way) are lost on restart.
- **Single-process**: The engine is single-threaded; very high event rates may require
  parallelising the rule evaluation step.
- **No automatic rule hot-reload**: Changing `thresholds.yaml` requires a restart.
- **VirusTotal free tier**: The free API is limited to 4 requests/minute.

### Suggested Future Enhancements

1. **Persistent correlation state** — Serialise sliding windows to Redis or disk for crash recovery.
2. **Async/concurrent processing** — Use `asyncio` or `ThreadPoolExecutor` for rule evaluation.
3. **Rule hot-reload** — Watch `thresholds.yaml` with `watchdog` and reload on change.
4. **Additional enrichment** — AbuseIPDB, Shodan, internal asset DB lookups.
5. **Automated response actions** — Trigger firewall block via API upon rule match.
6. **Kibana alerting** — Create Elastic alerting rules on `soar-actions-*` index.
7. **Slack / email notifications** — Alert the SOC team on CRITICAL priority actions.
8. **Persistent deduplication** — Move the dedup cache to Redis for cross-restart dedup.
9. **Unit-test coverage 100%** — Add tests for `es_collector`, `es_writer`, and `virustotal`.
10. **Docker Compose** — Add a `docker-compose.yml` to spin up the full stack locally.

---
