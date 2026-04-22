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
8. [Simulation Mode (End-to-End Testing)](#simulation-mode-end-to-end-testing)
9. [How to Add New Rules](#how-to-add-new-rules)
10. [Action Document Schema](#action-document-schema)
11. [Kibana Dashboard Guide](#kibana-dashboard-guide)
12. [VirusTotal Integration](#virustotal-integration)
13. [Module Reference](#module-reference)
14. [Running Tests](#running-tests)
15. [Limitations & Future Work](#limitations--future-work)

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
├── simulator/                   # ← NEW: Simulation Mode
│   ├── event_generator.py       # Synthetic Suricata event factory (6 scenarios)
│   ├── sim_publisher.py         # Bulk-publish to sim index with rate limiting
│   ├── scenario_runner.py       # generate + publish orchestrator
│   ├── replay_runner.py         # Replay JSON files into sim index
│   ├── scenarios/               # Scenario definition JSON files
│   │   ├── port_scan.json
│   │   ├── ssh_bruteforce.json
│   │   ├── web_attack.json
│   │   ├── malware_or_c2.json
│   │   ├── dns_suspicious.json
│   │   └── dos_or_flood.json
│   └── sample_data/             # Pre-baked event arrays for replay
│       ├── sample_port_scan.json
│       ├── sample_ssh_bruteforce.json
│       ├── sample_web_attack.json
│       ├── sample_malware_c2.json
│       ├── sample_dns_suspicious.json
│       └── sample_dos_flood.json
│
├── simulate.py                  # ← NEW: Simulation Mode CLI entrypoint
│
└── tests/
    ├── sample_events.py         # 10 mock Suricata events
    ├── test_normalizer.py
    ├── test_correlator.py
    ├── test_rules.py
    ├── test_action_builder.py
    └── test_simulator.py        # ← NEW: Simulator unit tests
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
| `SIM_INDEX` | `soar-simulation` | Simulation mode index name |
| `SIM_RATE_PER_SECOND` | `10` | Simulator publish rate (docs/s) |

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

## Simulation Mode (End-to-End Testing)

Simulation Mode lets you inject synthetic Suricata-style alert events into a
dedicated Elasticsearch index (`soar-simulation`) and then run the live engine
against that index — validating the full pipeline without real Filebeat or
Suricata infrastructure.

**Key characteristics:**
- Schema-identical to real Filebeat events (normalizer sees no difference)
- Completely isolated from `filebeat-*` live traffic
- Six built-in attack scenarios, configurable IP / count / rate
- Replay from any JSON file of raw Suricata documents
- Re-timestamps events to `now` so the checkpoint-based poller picks them up

---

### CLI Reference

```bash
# List available scenarios
python simulate.py list

# Generate and publish a scenario
python simulate.py run --scenario ssh_bruteforce
python simulate.py run --scenario port_scan --count 30 --rate 10
python simulate.py run --scenario malware_or_c2 --src-ip 10.0.0.55 --count 15

# Replay a pre-baked JSON sample file
python simulate.py replay --file simulator/sample_data/sample_ssh_bruteforce.json
python simulate.py replay --file simulator/sample_data/sample_dos_flood.json --rate 20

# Clear the simulation index
python simulate.py clear
```

**Available scenarios:**

| Scenario | Rule Triggered | Default Count |
|---|---|---|
| `port_scan` | SOAR-001 | 20 |
| `ssh_bruteforce` | SOAR-002 | 20 |
| `web_attack` | SOAR-003 | 20 |
| `malware_or_c2` | SOAR-004 + SOAR-008 | 20 |
| `dns_suspicious` | SOAR-005 | 20 |
| `dos_or_flood` | SOAR-006 | 20 |

---

### Step-by-Step End-to-End Test

#### Prerequisites

- Running Elasticsearch 8.x (local or remote)
- SOAR engine installed and `.env` configured

#### Step 1 — Inject a scenario

```powershell
# Publish 25 SSH brute-force alerts from a simulated attacker
python simulate.py run --scenario ssh_bruteforce --count 25 --rate 5
```

You should see output like:
```
✓ Published 25 events for scenario 'ssh_bruteforce' → index 'soar-simulation'
  Now run the engine: python main.py --once  (with ES_SOURCE_INDEX=soar-simulation)
```

#### Step 2 — Run the SOAR engine against the simulation index

```powershell
# Tell the engine to read from the simulation index
$env:ES_SOURCE_INDEX = "soar-simulation"

# Run a single processing cycle
python main.py --mode live --once --reset-checkpoint
```

The engine will:
1. Collect the 25 injected events from `soar-simulation`
2. Normalise them through `EventNormalizer`
3. Build correlation stats via `CorrelationState`
4. Evaluate all 8 rules → **SOAR-002 fires** (SSH brute-force threshold exceeded)
5. Write action document to `soar-actions-YYYY.MM.DD`

#### Step 3 — Verify in Kibana

1. Open Kibana → **Discover**
2. Select index pattern **`soar-actions-*`**
3. Add filter: `attack_type: ssh_bruteforce`
4. You should see action documents with `priority: HIGH` and detailed `reasons[]`

#### Tip: Run all scenarios at once

```powershell
$scenarios = @("port_scan","ssh_bruteforce","web_attack","malware_or_c2","dns_suspicious","dos_or_flood")
foreach ($s in $scenarios) {
    python simulate.py run --scenario $s --count 30
}
$env:ES_SOURCE_INDEX = "soar-simulation"
python main.py --mode live --once --reset-checkpoint
```

---

### Makefile Shortcuts

```bash
make sim-list                              # List scenarios
make sim-run SCENARIO=ssh_bruteforce       # Run a scenario
make sim-run SCENARIO=dos_or_flood SIM_COUNT=80 SIM_RATE=20
make sim-replay SIM_FILE=simulator/sample_data/sample_malware_c2.json
make sim-clear                             # Reset the sim index
```

---

### Adding Custom Replay Files

You can replay any JSON file containing an array of raw Suricata `_source` documents.
The minimum required structure per document:

```json
[
  {
    "@timestamp": "2024-06-01T10:00:00.000Z",
    "event": {"type": "alert", "kind": "alert"},
    "suricata": {
      "eve": {
        "src_ip": "1.2.3.4",
        "dest_ip": "10.0.0.1",
        "dest_port": 22,
        "proto": "tcp",
        "alert": {
          "signature": "ET SCAN SSH BruteForce Tool",
          "signature_id": 2001219,
          "category": "Attempted Administrator Privilege Gain",
          "severity": 1
        }
      }
    },
    "host": {"name": "my-sensor"},
    "risk_score": 80.0
  }
]
```

The replayer re-timestamps all documents to `now`, so you do not need to
manually update timestamps.

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

*Built for the Graduation Project — Faculty of Computer & Information Sciences, 2025/2026.*
