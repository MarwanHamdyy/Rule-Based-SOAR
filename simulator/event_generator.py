"""
simulator/event_generator.py
------------------------------
Stateless factory that produces raw Suricata-style Elasticsearch _source
documents for six attack scenarios.

All generated documents use the Filebeat 7 nested schema
(``suricata.eve.*``) which the existing EventNormalizer already handles.

Usage::

    gen = EventGenerator()
    docs = gen.generate("ssh_bruteforce", src_ip="10.0.0.5", count=20)
    # → list of 20 raw dicts ready for ES indexing / normalisation
"""

from __future__ import annotations

import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Scenario definitions: static alert templates per attack type
# ---------------------------------------------------------------------------

_PORT_SCAN_SIGS = [
    ("ET SCAN Nmap SYN Scan",              2000537, "Port Scan",      3),
    ("ET SCAN Nmap OS Detection",           2000538, "Port Scan",      3),
    ("ET SCAN Potential SSH Scan",          2001219, "Port Scan",      3),
    ("ET SCAN Suspicious Rapid Port Scan", 2009582, "Attempted Recon", 2),
    ("ET SCAN NMAP -sV Version Scan",      2000545, "Port Scan",      3),
]

_SSH_BRUTEFORCE_SIGS = [
    ("ET SCAN SSH BruteForce Tool with fake PUTTY version", 2001219, "Attempted Administrator Privilege Gain", 1),
    ("ET SCAN Potential SSH Brute Force Attempt",           2001722, "Attempted Administrator Privilege Gain", 1),
    ("ET SSH Bruteforce Banner Response",                   2019876, "Attempted Administrator Privilege Gain", 2),
    ("ET BRUTE SSH Authentication Failure",                 2003195, "Attempted Admin Privilege Gain",         1),
    ("ET SCAN SSH Scanner",                                 2001721, "Attempted Administrator Privilege Gain", 2),
]

_WEB_ATTACK_SIGS = [
    ("ET WEB_SERVER SQL Injection Attempt -- SELECT FROM",    2006445, "Web Application Attack", 1),
    ("ET WEB_SERVER XSS Attempt in URI",                      2009600, "Web Application Attack", 1),
    ("ET WEB_SERVER PHP Remote File Inclusion Attempt",       2002083, "Web Application Attack", 2),
    ("ET WEB_SERVER Possible SQL Injection UNION SELECT",     2006444, "Web Application Attack", 1),
    ("ET WEB_SERVER Directory Traversal Attempt (../..)",     2100498, "Web Application Attack", 2),
    ("ET WEB_SERVER HTTP TRACE Method Request",               2009693, "Web Application Attack", 3),
]

_MALWARE_C2_SIGS = [
    ("ET MALWARE Cobalt Strike Beacon Observed",           2019714, "Malware Command and Control Activity Detected", 1),
    ("ET MALWARE Metasploit Payload Detected",             2012887, "Malware Command and Control Activity Detected", 1),
    ("ET TROJAN Generic Trojan C2 Beacon Observed",        2022908, "A Network Trojan was Detected",                1),
    ("ET MALWARE Win32/Emotet C2 Communication",           2031449, "Malware Command and Control Activity Detected", 1),
    ("ET MALWARE Possible Ransomware C2 Beacon",           2033647, "Malware Command and Control Activity Detected", 1),
    ("ET TROJAN APT RAT Checkin",                          2027929, "A Network Trojan was Detected",                1),
]

_DNS_SUSPICIOUS_SIGS = [
    ("ET DNS DNS Tunnel Activity Detected",                         2027865, "DNS Exfiltration",                  2),
    ("ET DNS Query for .onion Proxy Domain",                        2022918, "Potentially Bad Traffic",            2),
    ("ET DNS Non-DNS or Non-Compliant DNS",                         2017941, "Potentially Bad Traffic",            3),
    ("ET DNS Suspicious DNS Query for DGA Domain",                  2035999, "Potentially Bad Traffic",            2),
    ("ET DNS Query to Suspicious TLD (.cc)",                        2034578, "Potentially Bad Traffic",            3),
    ("ET DNS High Frequency DNS Requests indicating DNS Tunneling", 2027867, "DNS Exfiltration",                  1),
]

_DOS_FLOOD_SIGS = [
    ("ET DOS Possible TCP SYN Flood Attack",                 2002992, "Denial of Service Attack", 2),
    ("ET DOS Possible UDP Flood",                            2002994, "Denial of Service Attack", 2),
    ("ET DOS Possible NTP DDoS Inbound Frequent Un-Authed MON_LIST Requests", 2017919, "Denial of Service Attack", 2),
    ("ET DOS Possible SLOWLORIS DoS Attack Tool",           2012735, "Denial of Service Attack", 2),
    ("ET DOS Excessive HTTP Requests Indicating Possible DDoS", 2012134, "Denial of Service Attack", 1),
    ("ET DOS ICMP Flood",                                    2101411, "Denial of Service Attack", 2),
]

_SCENARIO_MAP: dict[str, list[tuple]] = {
    "port_scan":       _PORT_SCAN_SIGS,
    "ssh_bruteforce":  _SSH_BRUTEFORCE_SIGS,
    "web_attack":      _WEB_ATTACK_SIGS,
    "malware_or_c2":   _MALWARE_C2_SIGS,
    "dns_suspicious":  _DNS_SUSPICIOUS_SIGS,
    "dos_or_flood":    _DOS_FLOOD_SIGS,
}

# Destination ports per scenario
_SCENARIO_DST_PORTS: dict[str, list[int]] = {
    "port_scan":      list(range(20, 1024)),      # wide sweep
    "ssh_bruteforce":  [22],
    "web_attack":      [80, 443, 8080, 8443],
    "malware_or_c2":   [443, 4444, 8080, 80],
    "dns_suspicious":  [53],
    "dos_or_flood":    [80, 443, 53],
}

_SCENARIO_PROTOS: dict[str, list[str]] = {
    "port_scan":      ["tcp"],
    "ssh_bruteforce":  ["tcp"],
    "web_attack":      ["tcp"],
    "malware_or_c2":   ["tcp"],
    "dns_suspicious":  ["udp"],
    "dos_or_flood":    ["tcp", "udp", "icmp"],
}

_SCENARIO_DST_IPS: dict[str, list[str]] = {
    "port_scan":      ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5",
                       "10.0.0.6", "10.0.0.7", "10.0.0.8"],
    "ssh_bruteforce":  ["10.0.0.20", "10.0.0.21"],
    "web_attack":      ["10.0.0.30", "10.0.0.31"],
    "malware_or_c2":   ["185.220.101.45", "45.33.32.156", "198.51.100.1"],
    "dns_suspicious":  ["8.8.8.8", "1.1.1.1"],
    "dos_or_flood":    ["10.0.0.5", "10.0.0.100"],
}

_SCENARIO_RISK_SCORES: dict[str, tuple[float, float]] = {
    "port_scan":      (30.0, 55.0),
    "ssh_bruteforce":  (65.0, 90.0),
    "web_attack":      (55.0, 85.0),
    "malware_or_c2":   (80.0, 99.0),
    "dns_suspicious":  (45.0, 75.0),
    "dos_or_flood":    (50.0, 80.0),
}


class EventGenerator:
    """
    Generates synthetic Suricata alert documents for simulation scenarios.

    All documents are schema-compatible with the existing ``EventNormalizer``
    (Filebeat 7 / ``suricata.eve.*`` nested layout).

    Args:
        sensor_name:   Hostname injected into ``host.name`` (default: ``sim-sensor-01``).
        interval_ms:   Milliseconds between consecutive event timestamps (default: 500).
        sim_index:     Value injected into ``_es_index`` metadata field.
    """

    SCENARIOS = list(_SCENARIO_MAP.keys())

    def __init__(
        self,
        sensor_name: str = "sim-sensor-01",
        interval_ms: int = 500,
        sim_index: str = "soar-simulation",
    ) -> None:
        self.sensor_name = sensor_name
        self.interval_ms = interval_ms
        self.sim_index = sim_index

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(
        self,
        scenario: str,
        src_ip: str = "192.168.100.99",
        count: int = 20,
        start_time: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """
        Generate *count* raw Suricata alert documents for *scenario*.

        Args:
            scenario:   One of the supported scenario names (see ``SCENARIOS``).
            src_ip:     Simulated attacker source IP.
            count:      Number of documents to generate.
            start_time: First event timestamp (defaults to now – 60 s).

        Returns:
            List of raw ES ``_source`` dicts with ``_es_index`` / ``_es_id`` injected.

        Raises:
            ValueError: If *scenario* is not recognised.
        """
        if scenario not in _SCENARIO_MAP:
            raise ValueError(
                f"Unknown scenario '{scenario}'. Available: {self.SCENARIOS}"
            )

        if start_time is None:
            start_time = datetime.now(timezone.utc) - timedelta(seconds=60)

        sigs = _SCENARIO_MAP[scenario]
        dst_ports = _SCENARIO_DST_PORTS[scenario]
        dst_ips = _SCENARIO_DST_IPS[scenario]
        protos = _SCENARIO_PROTOS[scenario]
        risk_min, risk_max = _SCENARIO_RISK_SCORES[scenario]

        docs: list[dict[str, Any]] = []
        for i in range(count):
            ts = start_time + timedelta(milliseconds=self.interval_ms * i)
            sig, sig_id, category, severity = random.choice(sigs)  # noqa: S311
            dst_port = dst_ports[i % len(dst_ports)]
            dst_ip = random.choice(dst_ips)  # noqa: S311
            proto = random.choice(protos)  # noqa: S311
            risk_score = round(random.uniform(risk_min, risk_max), 1)  # noqa: S311
            src_port = random.randint(10000, 65535)  # noqa: S311

            doc: dict[str, Any] = {
                "@timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                "_es_index": self.sim_index,
                "_es_id": f"sim-{scenario}-{uuid.uuid4().hex[:12]}",
                "event": {"type": "alert", "kind": "alert"},
                "suricata": {
                    "eve": {
                        "src_ip": src_ip,
                        "src_port": src_port,
                        "dest_ip": dst_ip,
                        "dest_port": dst_port,
                        "proto": proto,
                        "alert": {
                            "signature": sig,
                            "signature_id": sig_id,
                            "category": category,
                            "severity": severity,
                        },
                        "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
                    }
                },
                "host": {"name": self.sensor_name},
                "risk_score": risk_score,
                # Simulator metadata (not consumed by pipeline)
                "_sim_scenario": scenario,
            }
            docs.append(doc)

        logger.info(
            "Generated %d synthetic events for scenario '%s' from src_ip=%s.",
            count, scenario, src_ip,
        )
        return docs
