"""
simulate.py
-----------
CLI entrypoint for Simulation Mode.

TWO WAYS TO RUN
===============

  OFFLINE (no Elasticsearch needed) – recommended for demos / local dev:
    python simulate.py offline --scenario ssh_bruteforce --count 25
    python simulate.py offline --scenario all --count 30
    python simulate.py offline --file simulator/sample_data/sample_malware_c2.json

  ONLINE (real Elasticsearch index):
    python simulate.py run    --scenario ssh_bruteforce --count 25
    python simulate.py replay --file simulator/sample_data/sample_malware_c2.json
    python simulate.py clear
    python simulate.py list

Usage examples (offline – zero dependencies)
============================================

  python simulate.py offline --scenario ssh_bruteforce
  python simulate.py offline --scenario all --count 30 --output results/actions.json
  python simulate.py offline --file simulator/sample_data/sample_port_scan.json
  python simulate.py list
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from simulator.event_generator import EventGenerator
from utils.config_loader import load_settings
from utils.logger import get_logger, setup_logging

import urllib3


# ---------------------------------------------------------------------------
# ES client (only built for online commands)
# ---------------------------------------------------------------------------

def build_es_client(cfg: dict):
    """Build an Elasticsearch client from settings."""
    from elasticsearch import Elasticsearch
    es_cfg = cfg.get("elasticsearch", {})
    host = es_cfg.get("host", "https://localhost:9200")
    kwargs: dict = {
        "hosts": [host],
        "verify_certs": bool(es_cfg.get("verify_certs", False)),
        "request_timeout": int(es_cfg.get("timeout", 30)),
    }
    api_key = os.environ.get("ES_API_KEY", "")
    if api_key:
        kwargs["api_key"] = api_key
    else:
        username = es_cfg.get("username", "elastic")
        password = es_cfg.get("password", "changeme")
        if username and password:
            kwargs["basic_auth"] = (username, password)
    if not kwargs["verify_certs"]:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    return Elasticsearch(**kwargs)


# ---------------------------------------------------------------------------
# Sub-command handlers
# ---------------------------------------------------------------------------

def cmd_offline(args: argparse.Namespace, cfg: dict) -> int:
    """
    OFFLINE mode: generate events → run full pipeline in memory → print results.
    No Elasticsearch required at all.
    """
    from simulator.offline_runner import OfflineRunner

    sim_cfg = cfg.get("simulation", {})
    src_ip  = args.src_ip or str(sim_cfg.get("default_src_ip", "192.168.100.99"))
    count   = args.count

    runner = OfflineRunner(config_dir=args.config_dir)

    all_actions = []

    # ---- scenario mode ----
    if args.file is None:
        scenarios_to_run = (
            EventGenerator.SCENARIOS if args.scenario == "all" else [args.scenario]
        )
        generator = EventGenerator(
            sensor_name=str(sim_cfg.get("sensor_name", "sim-sensor-01")),
            interval_ms=int(sim_cfg.get("interval_ms", 500)),
        )
        for scenario in scenarios_to_run:
            print(f"\n  ▶  Generating {count} events for scenario: {scenario} …")
            docs    = generator.generate(scenario, src_ip=src_ip, count=count)
            actions = runner.run_docs(docs)
            runner.print_results(actions, scenario=scenario)
            all_actions.extend(actions)

    # ---- file replay mode ----
    else:
        file_path = Path(args.file)
        if not file_path.exists():
            print(f"\n  ✘  File not found: {file_path}\n")
            return 1
        with file_path.open("r", encoding="utf-8") as fh:
            docs = json.load(fh)
        print(f"\n  ▶  Replaying {len(docs)} events from '{file_path.name}' …")
        all_actions = runner.run_docs(docs)
        runner.print_results(all_actions, scenario=file_path.stem)

    # ---- save output ----
    output_path = args.output or "output/actions.json"
    runner.save_results(all_actions, output_path)
    return 0


def cmd_list(args: argparse.Namespace, cfg: dict) -> int:  # noqa: ARG001
    """Print available scenario names."""
    print("\nAvailable simulation scenarios:")
    for name in EventGenerator.SCENARIOS:
        print(f"  • {name}")
    print('\n  (use "all" with --offline to run every scenario)\n')
    return 0


def cmd_run(args: argparse.Namespace, cfg: dict) -> int:
    """Generate and publish a synthetic scenario to Elasticsearch."""
    from simulator.scenario_runner import ScenarioRunner
    from simulator.sim_publisher import SimPublisher

    sim_cfg   = cfg.get("simulation", {})
    sim_index = str(os.environ.get("SIM_INDEX", sim_cfg.get("index", "soar-simulation")))
    rate      = int(os.environ.get("SIM_RATE_PER_SECOND", "") or args.rate or sim_cfg.get("rate_per_second", 10))
    src_ip    = args.src_ip or str(sim_cfg.get("default_src_ip", "192.168.100.99"))

    get_logger("simulate.run").info(
        "Scenario='%s' | src_ip=%s | count=%d | rate=%d/s | index='%s'",
        args.scenario, src_ip, args.count, rate, sim_index,
    )

    es = build_es_client(cfg)
    publisher = SimPublisher(es, sim_index=sim_index, rate_per_second=rate)
    publisher.ensure_index()

    generator = EventGenerator(
        sensor_name=str(sim_cfg.get("sensor_name", "sim-sensor-01")),
        interval_ms=int(sim_cfg.get("interval_ms", 500)),
        sim_index=sim_index,
    )
    published = ScenarioRunner(publisher=publisher, generator=generator).run(
        args.scenario, src_ip=src_ip, count=args.count
    )
    print(f"\n✓ Published {published} events for scenario '{args.scenario}' → index '{sim_index}'")
    print(f"  Now run the engine: python main.py --once  (with ES_SOURCE_INDEX={sim_index})\n")
    return 0 if published > 0 else 1


def cmd_replay(args: argparse.Namespace, cfg: dict) -> int:
    """Publish events from a JSON file into Elasticsearch."""
    from simulator.replay_runner import ReplayRunner
    from simulator.sim_publisher import SimPublisher

    sim_cfg   = cfg.get("simulation", {})
    sim_index = str(os.environ.get("SIM_INDEX", sim_cfg.get("index", "soar-simulation")))
    rate      = int(os.environ.get("SIM_RATE_PER_SECOND", "") or args.rate or sim_cfg.get("rate_per_second", 10))

    es = build_es_client(cfg)
    publisher = SimPublisher(es, sim_index=sim_index, rate_per_second=rate)
    publisher.ensure_index()

    published = ReplayRunner(publisher=publisher).replay(
        json_path=args.file, rate_per_second=rate
    )
    print(f"\n✓ Replayed {published} events from '{args.file}' → index '{sim_index}'")
    print(f"  Now run the engine: python main.py --once  (with ES_SOURCE_INDEX={sim_index})\n")
    return 0 if published > 0 else 1


def cmd_clear(args: argparse.Namespace, cfg: dict) -> int:  # noqa: ARG001
    """Delete all documents from the simulation index."""
    from simulator.sim_publisher import SimPublisher

    sim_cfg   = cfg.get("simulation", {})
    sim_index = str(os.environ.get("SIM_INDEX", sim_cfg.get("index", "soar-simulation")))

    es = build_es_client(cfg)
    deleted = SimPublisher(es, sim_index=sim_index).clear_index()
    print(f"\n✓ Cleared {deleted} documents from simulation index '{sim_index}'\n")
    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="simulate.py",
        description="Rule-Based SOAR – Simulation Mode CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Quick start (no Elasticsearch needed):\n"
            "  python simulate.py offline --scenario ssh_bruteforce\n"
            "  python simulate.py offline --scenario all --count 30\n"
            "  python simulate.py offline --file simulator/sample_data/sample_malware_c2.json\n"
        ),
    )
    parser.add_argument("--config-dir", default="./config",
                        help="Path to config directory (default: ./config).")
    parser.add_argument("--log-level", default=None,
                        help="Override log level (DEBUG|INFO|WARNING).")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    # ------------------------------------------------------------------ offline
    off_p = sub.add_parser(
        "offline",
        help="★ Run full pipeline in memory – NO Elasticsearch needed.",
        description=(
            "Generates synthetic events, runs them through the FULL SOAR\n"
            "pipeline (normalizer → correlator → rules → action builder)\n"
            "entirely in memory, then prints results to the console.\n\n"
            "No Elasticsearch, no Kibana, no network required."
        ),
    )
    off_mut = off_p.add_mutually_exclusive_group()
    off_mut.add_argument(
        "--scenario", "-s",
        choices=EventGenerator.SCENARIOS + ["all"],
        default="ssh_bruteforce",
        help="Attack scenario to simulate, or 'all' to run every scenario (default: ssh_bruteforce).",
    )
    off_mut.add_argument(
        "--file", "-f",
        help="Replay events from a JSON sample file instead of generating.",
    )
    off_p.add_argument("--src-ip", default=None,
                       help="Simulated attacker IP (default from config).")
    off_p.add_argument("--count", "-n", type=int, default=20,
                       help="Number of events to generate (default: 20).")
    off_p.add_argument(
        "--output", "-o", default="output/actions.json",
        help="File path to save JSON results (default: output/actions.json).",
    )

    # ------------------------------------------------------------------ list
    sub.add_parser("list", help="Print available scenario names.")

    # ------------------------------------------------------------------ run (online)
    run_p = sub.add_parser("run", help="[Needs ES] Generate and publish a scenario.")
    run_p.add_argument("--scenario", "-s", required=True,
                       choices=EventGenerator.SCENARIOS,
                       help="Attack scenario to simulate.")
    run_p.add_argument("--src-ip", default=None)
    run_p.add_argument("--count", "-n", type=int, default=20)
    run_p.add_argument("--rate", "-r", type=int, default=None)

    # ------------------------------------------------------------------ replay (online)
    replay_p = sub.add_parser("replay", help="[Needs ES] Replay a JSON file into ES.")
    replay_p.add_argument("--file", "-f", required=True)
    replay_p.add_argument("--rate", "-r", type=int, default=None)
    replay_p.add_argument("--no-retimestamp", action="store_true")

    # ------------------------------------------------------------------ clear (online)
    sub.add_parser("clear", help="[Needs ES] Delete all documents from the simulation index.")

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    cfg         = load_settings(args.config_dir)
    logging_cfg = cfg.get("logging", {})
    log_level   = args.log_level or str(logging_cfg.get("level", "WARNING"))

    # For offline mode, suppress noisy log output — user only cares about the table
    if getattr(args, "command", None) == "offline":
        log_level = args.log_level or "WARNING"

    setup_logging(
        level=log_level,
        log_file=str(logging_cfg.get("file", "./logs/soar.log")),
    )

    handlers = {
        "offline": cmd_offline,
        "list":    cmd_list,
        "run":     cmd_run,
        "replay":  cmd_replay,
        "clear":   cmd_clear,
    }

    try:
        rc = handlers[args.command](args, cfg)
        sys.exit(rc)
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(0)
    except Exception as exc:  # noqa: BLE001
        get_logger("simulate").critical("Fatal error: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
