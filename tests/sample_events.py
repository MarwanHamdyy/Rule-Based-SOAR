"""
tests/sample_events.py
-----------------------
Mock Suricata alert documents mimicking what Filebeat ships to Elasticsearch.
Used by all unit tests to avoid any Elasticsearch dependency.

``SAMPLE_EVENTS`` is a list of raw ES ``_source`` documents (with collector-
injected ``_es_index`` and ``_es_id`` fields).
"""

from __future__ import annotations

SAMPLE_EVENTS: list[dict] = [

    # ---------------------------------------------------------------
    # 1. Port Scan event – nmap SYN scan
    # ---------------------------------------------------------------
    {
        "@timestamp": "2024-06-01T10:00:00.000Z",
        "_es_index": "filebeat-8.12.0-2024.06.01",
        "_es_id": "evt-001",
        "event": {"type": "alert", "kind": "alert"},
        "suricata": {
            "eve": {
                "src_ip": "192.168.1.50",
                "src_port": 54321,
                "dest_ip": "10.0.0.5",
                "dest_port": 22,
                "proto": "tcp",
                "alert": {
                    "signature": "ET SCAN Nmap SYN Scan",
                    "signature_id": 2000537,
                    "category": "Port Scan",
                    "severity": 3,
                },
            }
        },
        "host": {"name": "ids-sensor-01"},
        "risk_score": 45.0,
    },

    # ---------------------------------------------------------------
    # 2. SSH Brute Force event
    # ---------------------------------------------------------------
    {
        "@timestamp": "2024-06-01T10:01:00.000Z",
        "_es_index": "filebeat-8.12.0-2024.06.01",
        "_es_id": "evt-002",
        "event": {"type": "alert", "kind": "alert"},
        "suricata": {
            "eve": {
                "src_ip": "203.0.113.10",
                "src_port": 4444,
                "dest_ip": "10.0.0.20",
                "dest_port": 22,
                "proto": "tcp",
                "alert": {
                    "signature": "ET SCAN SSH BruteForce Tool with fake PUTTY version",
                    "signature_id": 2001219,
                    "category": "Attempted Administrator Privilege Gain",
                    "severity": 1,
                },
            }
        },
        "host": {"name": "ids-sensor-01"},
        "risk_score": 80.0,
    },

    # ---------------------------------------------------------------
    # 3. SQL Injection attempt
    # ---------------------------------------------------------------
    {
        "@timestamp": "2024-06-01T10:02:00.000Z",
        "_es_index": "filebeat-8.12.0-2024.06.01",
        "_es_id": "evt-003",
        "event": {"type": "alert", "kind": "alert"},
        "suricata": {
            "eve": {
                "src_ip": "198.51.100.22",
                "src_port": 60000,
                "dest_ip": "10.0.0.30",
                "dest_port": 80,
                "proto": "tcp",
                "alert": {
                    "signature": "ET WEB_SERVER SQL Injection Attempt -- SELECT FROM",
                    "signature_id": 2006445,
                    "category": "Web Application Attack",
                    "severity": 1,
                },
            }
        },
        "host": {"name": "ids-sensor-02"},
        "risk_score": 75.0,
    },

    # ---------------------------------------------------------------
    # 4. Malware / C2 beacon
    # ---------------------------------------------------------------
    {
        "@timestamp": "2024-06-01T10:03:00.000Z",
        "_es_index": "filebeat-8.12.0-2024.06.01",
        "_es_id": "evt-004",
        "event": {"type": "alert", "kind": "alert"},
        "suricata": {
            "eve": {
                "src_ip": "10.0.0.15",
                "src_port": 49200,
                "dest_ip": "185.220.101.45",
                "dest_port": 443,
                "proto": "tcp",
                "alert": {
                    "signature": "ET MALWARE Cobalt Strike Beacon Observed",
                    "signature_id": 2019714,
                    "category": "Malware Command and Control Activity Detected",
                    "severity": 1,
                },
            }
        },
        "host": {"name": "ids-sensor-01"},
        "risk_score": 95.0,
    },

    # ---------------------------------------------------------------
    # 5. DNS Tunnelling suspicion
    # ---------------------------------------------------------------
    {
        "@timestamp": "2024-06-01T10:04:00.000Z",
        "_es_index": "filebeat-8.12.0-2024.06.01",
        "_es_id": "evt-005",
        "event": {"type": "alert", "kind": "alert"},
        "suricata": {
            "eve": {
                "src_ip": "10.0.0.25",
                "src_port": 54123,
                "dest_ip": "8.8.8.8",
                "dest_port": 53,
                "proto": "udp",
                "alert": {
                    "signature": "ET DNS DNS Tunnel Activity Detected",
                    "signature_id": 2027865,
                    "category": "DNS Exfiltration",
                    "severity": 2,
                },
            }
        },
        "host": {"name": "ids-sensor-02"},
        "risk_score": 60.0,
    },

    # ---------------------------------------------------------------
    # 6. DoS / SYN Flood
    # ---------------------------------------------------------------
    {
        "@timestamp": "2024-06-01T10:05:00.000Z",
        "_es_index": "filebeat-8.12.0-2024.06.01",
        "_es_id": "evt-006",
        "event": {"type": "alert", "kind": "alert"},
        "suricata": {
            "eve": {
                "src_ip": "192.0.2.100",
                "src_port": 0,
                "dest_ip": "10.0.0.5",
                "dest_port": 80,
                "proto": "tcp",
                "alert": {
                    "signature": "ET DOS Possible TCP SYN Flood Attack",
                    "signature_id": 2002992,
                    "category": "Denial of Service Attack",
                    "severity": 2,
                },
            }
        },
        "host": {"name": "ids-sensor-01"},
        "risk_score": 70.0,
    },

    # ---------------------------------------------------------------
    # 7. Lateral Movement – SMB access attempt
    # ---------------------------------------------------------------
    {
        "@timestamp": "2024-06-01T10:06:00.000Z",
        "_es_index": "filebeat-8.12.0-2024.06.01",
        "_es_id": "evt-007",
        "event": {"type": "alert", "kind": "alert"},
        "suricata": {
            "eve": {
                "src_ip": "10.0.0.50",
                "src_port": 49300,
                "dest_ip": "10.0.0.60",
                "dest_port": 445,
                "proto": "tcp",
                "alert": {
                    "signature": "ET EXPLOIT Possible SMB Pass-the-Hash Attack",
                    "signature_id": 2023449,
                    "category": "Lateral Movement",
                    "severity": 1,
                },
            }
        },
        "host": {"name": "ids-sensor-01"},
        "risk_score": 82.0,
    },

    # ---------------------------------------------------------------
    # 8. Generic high-severity alert (Severity 1, no specific category)
    # ---------------------------------------------------------------
    {
        "@timestamp": "2024-06-01T10:07:00.000Z",
        "_es_index": "filebeat-8.12.0-2024.06.01",
        "_es_id": "evt-008",
        "event": {"type": "alert", "kind": "alert"},
        "suricata": {
            "eve": {
                "src_ip": "172.16.0.9",
                "src_port": 12345,
                "dest_ip": "10.0.0.5",
                "dest_port": 3389,
                "proto": "tcp",
                "alert": {
                    "signature": "ET POLICY RDP to Internal Network",
                    "signature_id": 2010937,
                    "category": "Potentially Bad Traffic",
                    "severity": 1,
                },
            }
        },
        "host": {"name": "ids-sensor-02"},
        "risk_score": 55.0,
    },

    # ---------------------------------------------------------------
    # 9. ECS / Filebeat 8 flat schema variant
    # ---------------------------------------------------------------
    {
        "@timestamp": "2024-06-01T10:08:00.000Z",
        "_es_index": "filebeat-8.12.0-2024.06.01",
        "_es_id": "evt-009",
        "event": {"type": ["alert"], "kind": "alert"},
        "source": {"ip": "10.10.10.10", "port": 55000},
        "destination": {"ip": "10.0.0.80", "port": 443},
        "network": {"transport": "tcp"},
        "rule": {
            "name": "ET MALWARE Generic Trojan Dropper",
            "id": "2011001",
        },
        "agent": {"hostname": "ecs-sensor-01"},
        "risk_score": 90.0,
    },

    # ---------------------------------------------------------------
    # 10. Non-alert event (should be skipped by normalizer)
    # ---------------------------------------------------------------
    {
        "@timestamp": "2024-06-01T10:09:00.000Z",
        "_es_index": "filebeat-8.12.0-2024.06.01",
        "_es_id": "evt-010",
        "event": {"type": "flow", "kind": "event"},
        "suricata": {
            "eve": {
                "src_ip": "10.0.0.1",
                "dest_ip": "8.8.8.8",
                "proto": "udp",
            }
        },
    },
]


# Convenience: events by role for targeted test fixtures
PORT_SCAN_EVENT = SAMPLE_EVENTS[0]
SSH_BRUTE_EVENT = SAMPLE_EVENTS[1]
WEB_ATTACK_EVENT = SAMPLE_EVENTS[2]
MALWARE_C2_EVENT = SAMPLE_EVENTS[3]
DNS_EVENT = SAMPLE_EVENTS[4]
DOS_EVENT = SAMPLE_EVENTS[5]
LATERAL_EVENT = SAMPLE_EVENTS[6]
GENERIC_HIGH_EVENT = SAMPLE_EVENTS[7]
ECS_SCHEMA_EVENT = SAMPLE_EVENTS[8]
NON_ALERT_EVENT = SAMPLE_EVENTS[9]
