"""
tests/test_action_executor.py
-------------------------------
Unit tests for the ActionExecutor dispatcher.

Uses a mock DockerAdapter to verify dispatch, timeout handling,
result formatting, and error propagation without requiring a
real Docker daemon.
"""

import time
import pytest
from unittest.mock import MagicMock, patch

from actions.action_result import ActionResult
from actions.base_action import BaseAction
from actions.executor import ActionExecutor
from adapters.docker_adapter import DockerAdapter


# =====================================================================
#  Fixtures
# =====================================================================

@pytest.fixture
def mock_docker():
    """Create a mock DockerAdapter that returns success for all ops."""
    docker = MagicMock(spec=DockerAdapter)
    docker.dry_run = True
    docker._client = None
    docker.exec_command.return_value = (0, "ok")
    docker.block_ip_in_container.return_value = (0, "blocked")
    docker.unblock_ip_in_container.return_value = (0, "unblocked")
    docker.block_outbound_ip.return_value = (0, "blocked")
    docker.restart_container.return_value = True
    docker.disconnect_network.return_value = True
    docker.connect_network.return_value = True
    docker.capture_pcap.return_value = (0, "capturing")
    docker.lock_user_account.return_value = (0, "locked")
    docker.unlock_user_account.return_value = (0, "unlocked")
    return docker


@pytest.fixture
def executor(mock_docker):
    """Create an ActionExecutor in dry-run mode."""
    return ActionExecutor(
        docker=mock_docker,
        dry_run=True,
        catalog_path="simulator/sample_data/action_catalog.json",
        telemetry_log="logs/test_telemetry.jsonl",
        max_workers=2,
    )


@pytest.fixture
def base_context():
    """Standard test context dict."""
    return {
        "action_id": "test-001",
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.5",
        "container_id": "iot-device-1",
        "attack_type": "test_attack",
        "username": "admin",
        "source_mac": "aa:bb:cc:dd:ee:ff",
        "domain": "evil.example.com",
        "interface": "eth0",
    }


# =====================================================================
#  Discovery & Registration
# =====================================================================

class TestActionDiscovery:
    def test_actions_discovered(self, executor):
        """Verify that actions were auto-discovered from scripts/."""
        actions = executor.list_actions()
        assert len(actions) > 0, "No actions discovered"

    def test_act_001_registered(self, executor):
        """ACT-001 should always be registered."""
        assert executor.has_action("ACT-001")

    def test_act_035_registered(self, executor):
        """ACT-035 (Alert SOC) should be registered."""
        assert executor.has_action("ACT-035")

    def test_case_insensitive(self, executor):
        """Action IDs should be case-insensitive."""
        assert executor.has_action("act-001")
        assert executor.has_action("ACT-001")


# =====================================================================
#  Execution
# =====================================================================

class TestActionExecution:
    def test_execute_act_001(self, executor, base_context):
        """ACT-001 Block Source IP should execute in dry-run."""
        result = executor.execute("ACT-001", base_context)
        assert isinstance(result, ActionResult)
        assert result.status == "success"
        assert result.action_id == "ACT-001"
        assert result.action_name == "Block Source IP Address"
        assert result.duration_ms >= 0

    def test_execute_act_035(self, executor, base_context):
        """ACT-035 Alert SOC should succeed (log-only)."""
        result = executor.execute("ACT-035", base_context)
        assert result.status == "success"

    def test_execute_unknown_action(self, executor, base_context):
        """Executing a non-existent action returns failure."""
        result = executor.execute("ACT-999", base_context)
        assert result.status == "failure"
        assert "No implementation" in result.error

    def test_execute_by_name(self, executor, base_context):
        """execute_by_name should resolve action names."""
        result = executor.execute_by_name("Block Source IP Address", base_context)
        assert result.status == "success"
        assert result.action_id == "ACT-001"

    def test_result_has_elk_doc(self, executor, base_context):
        """ActionResult should produce a valid ELK document."""
        result = executor.execute("ACT-001", base_context)
        elk = result.to_elk_doc()
        assert "@timestamp" in elk
        assert elk["event.kind"] == "action_execution"
        assert elk["action.id"] == "ACT-001"


# =====================================================================
#  Result Formatting
# =====================================================================

class TestActionResult:
    def test_to_dict(self):
        r = ActionResult(action_id="ACT-001", status="success")
        d = r.to_dict()
        assert d["action_id"] == "ACT-001"
        assert d["status"] == "success"

    def test_to_json_line(self):
        r = ActionResult(action_id="ACT-001", status="success")
        line = r.to_json_line()
        assert '"ACT-001"' in line
        assert "\n" not in line  # single line

    def test_to_elk_doc_structure(self):
        r = ActionResult(
            action_id="ACT-001",
            action_name="Block Source IP Address",
            action_class="network_containment",
            status="success",
            exit_code=0,
            duration_ms=150,
        )
        doc = r.to_elk_doc()
        assert doc["event.outcome"] == "success"
        assert doc["action.class"] == "network_containment"
        assert doc["duration_ms"] == 150


# =====================================================================
#  Error Handling
# =====================================================================

class TestErrorHandling:
    def test_sanitization_error_captured(self, executor):
        """Bad IP should result in failure with sanitization error."""
        bad_context = {
            "action_id": "test",
            "source_ip": "; rm -rf /",  # injection attempt
            "container_id": "iot-device-1",
        }
        result = executor.execute("ACT-001", bad_context)
        assert result.status == "failure"
        assert "sanitization" in result.error.lower() or "Sanitization" in result.error

    def test_missing_action_handled(self, executor, base_context):
        """Non-existent actions return clean failure result."""
        result = executor.execute("ACT-000", base_context)
        assert result.status == "failure"


# =====================================================================
#  Cleanup
# =====================================================================

class TestCleanup:
    def test_shutdown(self, executor):
        """Shutdown should not raise."""
        executor.shutdown(wait=False)
