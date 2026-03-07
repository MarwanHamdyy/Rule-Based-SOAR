"""
main.py
--------
Entry point for the Rule-Based SOAR engine.

Usage:
    python main.py                  # live mode (default)
    python main.py --mode replay    # replay from REPLAY_FROM in .env / config
    python main.py --mode live --once  # single-pass, useful for testing

The engine pipeline on each poll cycle:
    ES Collector → Normalizer → Correlator → Rule Engine → Enrichment → Action Writer
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from elasticsearch import Elasticsearch

from actions.action_builder import ActionBuilder
from actions.es_writer import ESWriter
from collector.es_collector import ESCollector
from correlator.state_manager import CorrelationState
from enrichment.virustotal import VirusTotalEnricher
from mappings.framework_mapper import FrameworkMapper
from normalizer.event_normalizer import EventNormalizer
from rules.rule_engine import RuleEngine
from utils.checkpoint import Checkpoint
from utils.config_loader import load_settings
from utils.logger import get_logger, setup_logging


def build_es_client(cfg: dict) -> Elasticsearch:
    """Construct an Elasticsearch client from settings."""
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

    # Suppress TLS warnings when verify_certs is False
    if not kwargs["verify_certs"]:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    return Elasticsearch(**kwargs)


def process_batch(
    raw_docs: list[dict],
    normalizer: EventNormalizer,
    correlation_state: CorrelationState,
    rule_engine: RuleEngine,
    enricher: VirusTotalEnricher,
    action_builder: ActionBuilder,
    writer: ESWriter,
) -> int:
    """
    Run one batch of raw ES documents through the full pipeline.

    Returns:
        Number of action documents written.
    """
    actions_written = 0

    for raw in raw_docs:
        # -- Normalize --
        event = normalizer.normalize(raw)
        if event is None:
            continue

        # -- Correlate (add to sliding windows) --
        correlation_state.ingest(event)

        # -- Query correlation stats for this source IP --
        stats = correlation_state.query(event.src_ip)

        # -- Evaluate rules --
        matches = rule_engine.evaluate(event, stats)

        for match in matches:
            # -- Optional enrichment --
            enrichment = {}
            if enricher.is_enabled() and event.src_ip:
                enrichment = enricher.enrich(ip=event.src_ip)

            # -- Build action document --
            action_doc = action_builder.build(event, match, enrichment)

            # -- Write to ES --
            if writer.write(action_doc):
                actions_written += 1

    # Clean up expired correlation windows periodically
    correlation_state.purge_expired()

    return actions_written


def main() -> None:
    # ---- Argument parsing ----
    parser = argparse.ArgumentParser(
        description="Rule-Based SOAR Engine – processes Suricata alerts from Elasticsearch."
    )
    parser.add_argument(
        "--mode", choices=["live", "replay"], default=None,
        help="Override ENGINE_MODE from config (live|replay)."
    )
    parser.add_argument(
        "--config-dir", default="./config",
        help="Path to the config directory (default: ./config)."
    )
    parser.add_argument(
        "--once", action="store_true",
        help="Run a single poll cycle then exit (useful for testing)."
    )
    parser.add_argument(
        "--reset-checkpoint", action="store_true",
        help="Delete the checkpoint file before starting."
    )
    args = parser.parse_args()

    # ---- Load configuration ----
    cfg = load_settings(args.config_dir)
    engine_cfg = cfg.get("engine", {})
    logging_cfg = cfg.get("logging", {})

    # ---- Setup logging ----
    setup_logging(
        level=str(logging_cfg.get("level", "INFO")),
        log_file=str(logging_cfg.get("file", "./logs/soar.log")),
    )
    logger = get_logger("soar.main")
    logger.info("=" * 60)
    logger.info("  Rule-Based SOAR Engine starting up")
    logger.info("=" * 60)

    # ---- Determine engine mode ----
    mode = args.mode or str(engine_cfg.get("mode", "live"))
    logger.info("Engine mode: %s", mode)

    # ---- Build components ----
    es_client = build_es_client(cfg)

    checkpoint = Checkpoint(str(engine_cfg.get("checkpoint_file", "./data/checkpoint.json")))
    if args.reset_checkpoint:
        checkpoint.reset()

    vt_cfg = cfg.get("enrichment", {}).get("virustotal", {})
    enricher = VirusTotalEnricher(
        api_key=str(vt_cfg.get("api_key", "")),
        cache_ttl=int(vt_cfg.get("cache_ttl", 3600)),
        timeout=int(vt_cfg.get("timeout", 10)),
        enabled=bool(vt_cfg.get("enabled", False)),
    )

    collector = ESCollector(
        es_client=es_client,
        source_index=str(cfg.get("indices", {}).get("source", "filebeat-*")),
        checkpoint=checkpoint,
        max_results=int(engine_cfg.get("max_events_per_poll", 500)),
        mode=mode,
        replay_from=str(engine_cfg.get("replay_from", "")),
    )

    normalizer = EventNormalizer()

    window_cfg = cfg.get("thresholds", {}).get("correlation", {}).get("windows", {})
    correlation_state = CorrelationState(windows={
        "short":    int(window_cfg.get("short", 30)),
        "medium":   int(window_cfg.get("medium", 60)),
        "long":     int(window_cfg.get("long", 300)),
        "extended": int(window_cfg.get("extended", 900)),
    } if window_cfg else None)

    rule_config = cfg.get("thresholds", {}).get("rules", {})
    rule_engine = RuleEngine(rule_config)

    framework_mapper = FrameworkMapper()
    action_builder = ActionBuilder(framework_mapper=framework_mapper)

    target_prefix = str(cfg.get("indices", {}).get("target_prefix", "soar-actions"))
    dedup_secs = int(engine_cfg.get("dedup_window_seconds", 60))
    writer = ESWriter(es_client, index_prefix=target_prefix, dedup_window_secs=dedup_secs)
    writer.ensure_index_template()

    poll_interval = int(engine_cfg.get("poll_interval", 10))

    # ---- Main loop ----
    logger.info("Starting main processing loop (poll_interval=%ds)", poll_interval)
    try:
        while True:
            batch = collector.poll()
            if batch:
                written = process_batch(
                    batch, normalizer, correlation_state,
                    rule_engine, enricher, action_builder, writer,
                )
                logger.info(
                    "Cycle complete: %d events → %d action(s) written.",
                    len(batch), written,
                )
            else:
                logger.debug("No new events in this cycle.")

            if args.once:
                logger.info("--once flag set; exiting after single cycle.")
                break

            time.sleep(poll_interval)

    except KeyboardInterrupt:
        logger.info("Shutdown requested (Ctrl+C). Exiting cleanly.")
    except Exception as exc:
        logger.critical("Fatal error in main loop: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
