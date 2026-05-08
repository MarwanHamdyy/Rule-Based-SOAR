"""
playbook_runner.py
-------------------
CLI entry point for the SOAR Playbook Engine.

Reads environment.yaml for lab topology, connects to Elasticsearch
and the Docker daemon, then runs the playbook engine.

Usage:
    python playbook_runner.py                      # continuous mode
    python playbook_runner.py --once               # single poll cycle
    python playbook_runner.py --dry-run            # print steps, no execution
    python playbook_runner.py --source iot         # only IoT self-healing events
    python playbook_runner.py --attack ATK-017     # manually trigger one playbook
    python playbook_runner.py --list-attacks       # list all known attack IDs
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

import yaml
from elasticsearch import Elasticsearch

from actions.executor import ActionExecutor
from adapters.docker_adapter import DockerAdapter
from collector.iot_event_collector import IoTEventCollector
from playbooks.engine import PlaybookEngine
from playbooks.lookup import PlaybookLookup
from playbooks.executor import PlaybookExecutor
from playbooks.result_writer import PlaybookResultWriter
from playbook_scripts.registry import ScriptRegistry
from utils.checkpoint import Checkpoint
from utils.logger import setup_logging, get_logger

logger = get_logger(__name__)


def load_env_config(path: str = "config/environment.yaml") -> dict:
    """Load and interpolate environment.yaml with env variable overrides."""
    with open(path, "r", encoding="utf-8") as fh:
        raw = fh.read()

    # Simple ${VAR:default} substitution
    import re
    def replace(m):
        var, default = m.group(1), m.group(2)
        return os.environ.get(var, default)
    raw = re.sub(r"\$\{(\w+):([^}]*)\}", replace, raw)
    return yaml.safe_load(raw)


def build_es_client(env_config: dict) -> Elasticsearch:
    host = env_config.get("elk", {}).get("host", "http://localhost:9200")
    logger.info("Connecting to Elasticsearch at %s", host)
    return Elasticsearch([host])


def build_docker_adapter(env_config: dict, dry_run: bool) -> DockerAdapter:
    docker_cfg = env_config.get("docker", {})
    return DockerAdapter(
        docker_host=docker_cfg.get("host", "unix:///var/run/docker.sock"),
        quarantine_network=docker_cfg.get("quarantine_network", "quarantine_net"),
        dry_run=dry_run,
    )


def cmd_continuous(args, env_config):
    """Default: run engine forever."""
    es     = build_es_client(env_config)
    docker = build_docker_adapter(env_config, args.dry_run)
    engine = PlaybookEngine(
        es_client=es,
        docker=docker,
        env_config=env_config,
        dry_run=args.dry_run,
        poll_interval=env_config.get("playbook_engine", {}).get("poll_interval", 15),
    )

    if args.source == "iot":
        _run_iot_only(es, docker, env_config, args)
    else:
        engine.run_forever()


def cmd_once(args, env_config):
    """Single poll cycle."""
    es     = build_es_client(env_config)
    docker = build_docker_adapter(env_config, args.dry_run)
    engine = PlaybookEngine(
        es_client=es,
        docker=docker,
        env_config=env_config,
        dry_run=args.dry_run,
    )
    count = engine.run_once()
    print(f"[playbook_runner] Processed {count} action(s).")


def cmd_attack(args, env_config):
    """Manually trigger a playbook by ATK-NNN id."""
    lookup = PlaybookLookup()
    entry  = lookup.resolve_by_id(args.attack)
    if not entry:
        print(f"[ERROR] No entry found for {args.attack}")
        sys.exit(1)

    print(f"Triggering playbook: {entry['attack_id']} — {entry['attack_name']}")

    es     = build_es_client(env_config)
    docker = build_docker_adapter(env_config, args.dry_run)
    registry = ScriptRegistry(docker=docker, dry_run=args.dry_run)
    executor = PlaybookExecutor(
        registry=registry,
        env_config=env_config,
    )
    writer = PlaybookResultWriter(es_client=es)

    # Build a synthetic action doc for manual trigger
    action_doc = {
        "action_id":   f"manual-{args.attack}",
        "attack_type": entry["attack_name"].lower().replace(" ", "_"),
        "source_ip":   args.src_ip or "192.168.1.100",
        "container_id": args.container or "iot-device-1",
    }
    result = executor.run(action_doc, entry)
    writer.write(result)

    print(f"Result: success={result.success}  steps={result.passed_steps}/{result.total_steps}")


def cmd_list_attacks(args, env_config):
    """Print all known attack IDs and names."""
    lookup = PlaybookLookup()
    import json
    path = Path("simulator/sample_data/mitigation_catalog.json")
    with path.open() as fh:
        data = json.load(fh)
    for entry in data.get("mitigation_catalog", []):
        print(f"  {entry['attack_id']:10}  {entry['severity']:10}  {entry['attack_name']}")


def cmd_execute_action(args, env_config):
    """Execute a single action by ACT-NNN id."""
    docker = build_docker_adapter(env_config, args.dry_run)

    action_cfg = env_config.get("action_executor", {})
    executor = ActionExecutor(
        docker=docker,
        env_config=env_config,
        catalog_path=action_cfg.get(
            "catalog_path", "simulator/sample_data/action_catalog.json"
        ),
        dry_run=args.dry_run,
        max_workers=int(action_cfg.get("max_workers", 4)),
        telemetry_log=action_cfg.get(
            "telemetry_log", "logs/action_telemetry.jsonl"
        ),
    )

    if not executor.has_action(args.execute_action):
        # List available actions on miss
        print(f"[ERROR] No implementation for {args.execute_action}")
        print("\nAvailable actions:")
        for a in executor.list_actions():
            print(f"  {a['action_id']:10}  {a['action_name']}")
        sys.exit(1)

    context = {
        "action_id": f"manual-{args.execute_action}",
        "source_ip": args.src_ip or "192.168.1.100",
        "destination_ip": args.dst_ip or "0.0.0.0",
        "container_id": args.container or "iot-device-1",
        "attack_type": "manual_trigger",
        "username": args.username or "root",
        "interface": args.interface or "eth0",
        "domain": args.domain or "example.com",
        "source_mac": args.mac or "00:00:00:00:00:00",
        # From env config
        "dmz_network": env_config.get("docker", {}).get("dmz_network", "dmz_net"),
        "quarantine_network": env_config.get("docker", {}).get(
            "quarantine_network", "quarantine_net"
        ),
        "mqtt_broker_container": env_config.get("mqtt", {}).get(
            "broker_container", "iot-device-1"
        ),
        "mqtt_broker_port": env_config.get("mqtt", {}).get("broker_port", 1883),
        "mqtt_safe_state_topic": env_config.get("mqtt", {}).get(
            "safe_state_topic", "actuators/control"
        ),
        "mqtt_safe_state_payload": env_config.get("mqtt", {}).get(
            "safe_state_payload", "OFF"
        ),
    }

    print(f"Executing action: {args.execute_action}")
    result = executor.execute(args.execute_action, context)

    print(f"\n{'='*60}")
    print(f"  Action:   {result.action_id} — {result.action_name}")
    print(f"  Status:   {result.status}")
    print(f"  Duration: {result.duration_ms}ms")
    print(f"  Exit:     {result.exit_code}")
    print(f"  Output:   {result.output[:300]}")
    if result.error:
        print(f"  Error:    {result.error[:300]}")
    print(f"{'='*60}")

    executor.shutdown()


def _run_iot_only(es, docker, env_config, args):
    """Run IoT event collector + playbook engine in a loop."""
    elk_cfg = env_config.get("elk", {})
    checkpoint = Checkpoint(elk_cfg.get("iot_checkpoint_file", "./data/iot_checkpoint.json"))
    collector  = IoTEventCollector(es_client=es, checkpoint=checkpoint)
    lookup     = PlaybookLookup()
    registry   = ScriptRegistry(docker=docker, dry_run=args.dry_run)
    executor   = PlaybookExecutor(registry=registry, env_config=env_config)
    writer     = PlaybookResultWriter(es_client=es)
    poll_interval = env_config.get("playbook_engine", {}).get("poll_interval", 15)

    logger.info("Running IoT-only event collector loop")
    try:
        while True:
            events = collector.poll()
            for event in events:
                entry = lookup.resolve(event["attack_type"])
                if entry:
                    result = executor.run(event, entry)
                    writer.write(result)
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        logger.info("IoT collector stopped.")


def main():
    setup_logging()

    parser = argparse.ArgumentParser(
        description="Ruled-SOAR Playbook Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--once",          action="store_true",  help="Single poll cycle, then exit")
    parser.add_argument("--dry-run",       action="store_true",  help="Log steps, do not execute scripts")
    parser.add_argument("--source",        choices=["all", "suricata", "iot"], default="all",
                        help="Event source to process (default: all)")
    parser.add_argument("--attack",        metavar="ATK-NNN",    help="Manually trigger a playbook by attack ID")
    parser.add_argument("--src-ip",        metavar="IP",         help="Source IP for manual trigger")
    parser.add_argument("--container",     metavar="NAME",       help="Container ID for manual trigger")
    parser.add_argument("--list-attacks",  action="store_true",  help="List all defined attack IDs and exit")
    parser.add_argument("--execute-action", metavar="ACT-NNN",   help="Execute a single action by ACT-NNN ID")
    parser.add_argument("--dst-ip",        metavar="IP",         help="Destination IP for action trigger")
    parser.add_argument("--username",      metavar="USER",       help="Username for identity actions")
    parser.add_argument("--interface",     metavar="IFACE",      help="Network interface (default: eth0)")
    parser.add_argument("--domain",        metavar="DOMAIN",     help="Domain name for DNS actions")
    parser.add_argument("--mac",           metavar="MAC",        help="MAC address for MAC-based actions")
    parser.add_argument("--config",        default="config/environment.yaml",
                        help="Path to environment.yaml (default: config/environment.yaml)")

    args = parser.parse_args()

    try:
        env_config = load_env_config(args.config)
    except FileNotFoundError:
        print(f"[ERROR] Config file not found: {args.config}")
        sys.exit(1)

    if args.list_attacks:
        cmd_list_attacks(args, env_config)
    elif args.execute_action:
        cmd_execute_action(args, env_config)
    elif args.attack:
        cmd_attack(args, env_config)
    elif args.once:
        cmd_once(args, env_config)
    else:
        cmd_continuous(args, env_config)


if __name__ == "__main__":
    main()
