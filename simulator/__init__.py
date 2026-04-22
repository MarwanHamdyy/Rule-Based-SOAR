"""
simulator/
-----------
Simulation Mode for the Rule-Based SOAR Engine.

Provides synthetic Suricata-style alert generation and replay capabilities
to enable end-to-end testing without real Filebeat / Suricata infrastructure.

Public surface:
    - EventGenerator   – builds raw ES documents per scenario
    - SimPublisher     – indexes documents into a dedicated simulation index
    - ScenarioRunner   – generate + publish in one call
    - ReplayRunner     – replay JSON files into the simulation index
"""

from simulator.event_generator import EventGenerator
from simulator.offline_runner import OfflineRunner
from simulator.sim_publisher import SimPublisher
from simulator.scenario_runner import ScenarioRunner
from simulator.replay_runner import ReplayRunner

__all__ = [
    "EventGenerator",
    "OfflineRunner",
    "SimPublisher",
    "ScenarioRunner",
    "ReplayRunner",
]
