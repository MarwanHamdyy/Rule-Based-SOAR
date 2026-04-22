"""
simulator/scenario_runner.py
------------------------------
Orchestrates a full simulate cycle: generate events → publish to ES.

Usage::

    runner = ScenarioRunner(publisher=pub, generator=gen)
    total  = runner.run("ssh_bruteforce", src_ip="203.0.113.10", count=25)
"""

from __future__ import annotations

from datetime import datetime, timezone

from simulator.event_generator import EventGenerator
from simulator.sim_publisher import SimPublisher
from utils.logger import get_logger

logger = get_logger(__name__)


class ScenarioRunner:
    """
    High-level orchestrator that combines :class:`EventGenerator` and
    :class:`SimPublisher` into a single ``run()`` call.

    Args:
        publisher:  A configured :class:`SimPublisher` instance.
        generator:  A configured :class:`EventGenerator` instance.
    """

    def __init__(
        self,
        publisher: SimPublisher,
        generator: EventGenerator | None = None,
    ) -> None:
        self.publisher = publisher
        self.generator = generator or EventGenerator()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self,
        scenario: str,
        src_ip: str = "192.168.100.99",
        count: int = 20,
        start_time: datetime | None = None,
    ) -> int:
        """
        Generate and publish events for a single *scenario*.

        Args:
            scenario:   Attack scenario name (e.g. ``"ssh_bruteforce"``).
            src_ip:     Simulated attacker source IP address.
            count:      Number of alert documents to generate.
            start_time: Timestamp for the first generated event
                        (defaults to now – 60 s so correlation windows get
                        populated before the engine polls).

        Returns:
            Number of documents published to Elasticsearch.
        """
        if start_time is None:
            start_time = datetime.now(timezone.utc)

        logger.info(
            "ScenarioRunner: starting scenario='%s' src_ip=%s count=%d",
            scenario, src_ip, count,
        )

        docs = self.generator.generate(
            scenario=scenario,
            src_ip=src_ip,
            count=count,
            start_time=start_time,
        )
        published = self.publisher.publish(docs)
        logger.info(
            "ScenarioRunner: scenario='%s' complete – %d docs published.",
            scenario, published,
        )
        return published

    def run_all(
        self,
        scenarios: list[str] | None = None,
        src_ip: str = "192.168.100.99",
        count: int = 20,
    ) -> dict[str, int]:
        """
        Run multiple scenarios sequentially.

        Args:
            scenarios: List of scenario names to run.  Defaults to all.
            src_ip:    Attacker source IP (same for all scenarios unless overridden).
            count:     Events per scenario.

        Returns:
            Mapping of ``{scenario_name: docs_published}``.
        """
        if scenarios is None:
            scenarios = EventGenerator.SCENARIOS

        results: dict[str, int] = {}
        for scenario in scenarios:
            try:
                results[scenario] = self.run(scenario, src_ip=src_ip, count=count)
            except ValueError as exc:
                logger.error("Skipping unknown scenario '%s': %s", scenario, exc)
                results[scenario] = 0

        logger.info("ScenarioRunner.run_all complete: %s", results)
        return results
