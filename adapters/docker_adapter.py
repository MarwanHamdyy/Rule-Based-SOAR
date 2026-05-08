"""
adapters/docker_adapter.py
--------------------------
Wrapper around the Docker SDK to manage IoT containers running
in the EVE-NG emulated environment.

All destructive actions (network disconnect, exec, restart) respect
the dry_run flag from environment.yaml so they can be tested safely.
"""

from __future__ import annotations

import logging
import time
from typing import Any

try:
    import docker
    from docker.errors import NotFound, APIError
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False

logger = logging.getLogger(__name__)


class DockerAdapter:
    """
    Manages IoT Docker containers in the emulated environment.

    Args:
        docker_host:        Docker daemon URI (unix socket or tcp).
        quarantine_network: Docker network name for isolated containers.
        dry_run:            If True, log actions but do not execute them.
    """

    def __init__(
        self,
        docker_host: str = "unix:///var/run/docker.sock",
        quarantine_network: str = "quarantine_net",
        dry_run: bool = False,
    ) -> None:
        self.quarantine_network = quarantine_network
        self.dry_run = dry_run

        if not DOCKER_AVAILABLE:
            logger.warning(
                "docker SDK not installed — DockerAdapter running in stub mode. "
                "Install it with: pip install docker"
            )
            self._client = None
            return

        try:
            self._client = docker.DockerClient(base_url=docker_host)
            self._client.ping()
            logger.info("DockerAdapter connected to %s", docker_host)
        except Exception as exc:  # noqa: BLE001
            logger.error("DockerAdapter: cannot connect to Docker: %s", exc)
            self._client = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def exec_command(
        self,
        container_id: str,
        cmd: str | list[str],
        timeout: int = 10,
    ) -> tuple[int, str]:
        """
        Run a shell command inside a container.

        Returns:
            (exit_code, output_text)
        """
        if self.dry_run:
            logger.info("[DRY-RUN] exec in %s: %s", container_id, cmd)
            return (0, "dry-run")

        if not self._client:
            return (1, "docker not available")

        try:
            container = self._client.containers.get(container_id)
            result = container.exec_run(
                cmd if isinstance(cmd, list) else ["sh", "-c", cmd],
                stdout=True,
                stderr=True,
                demux=False,
            )
            output = (result.output or b"").decode("utf-8", errors="replace")
            logger.debug("exec %s → exit=%d  out=%s", cmd, result.exit_code, output[:200])
            return (result.exit_code, output)
        except NotFound:
            logger.error("Container not found: %s", container_id)
            return (1, f"container {container_id} not found")
        except APIError as exc:
            logger.error("Docker API error on exec: %s", exc)
            return (1, str(exc))

    def restart_container(self, container_id: str, timeout: int = 10) -> bool:
        """Restart a container. Returns True on success."""
        if self.dry_run:
            logger.info("[DRY-RUN] restart container: %s", container_id)
            return True

        if not self._client:
            return False

        try:
            container = self._client.containers.get(container_id)
            container.restart(timeout=timeout)
            logger.info("Restarted container: %s", container_id)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to restart %s: %s", container_id, exc)
            return False

    def disconnect_network(self, container_id: str, network_name: str) -> bool:
        """
        Disconnect a container from a network (network isolation).
        Returns True on success.
        """
        if self.dry_run:
            logger.info("[DRY-RUN] disconnect %s from %s", container_id, network_name)
            return True

        if not self._client:
            return False

        try:
            network = self._client.networks.get(network_name)
            network.disconnect(container_id, force=True)
            logger.info("Disconnected %s from %s", container_id, network_name)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to disconnect %s from %s: %s", container_id, network_name, exc)
            return False

    def connect_network(self, container_id: str, network_name: str) -> bool:
        """
        Connect a container to a network (e.g., quarantine network).
        Returns True on success.
        """
        if self.dry_run:
            logger.info("[DRY-RUN] connect %s to %s", container_id, network_name)
            return True

        if not self._client:
            return False

        try:
            network = self._client.networks.get(network_name)
            network.connect(container_id)
            logger.info("Connected %s to %s", container_id, network_name)
            return True
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to connect %s to %s: %s", container_id, network_name, exc)
            return False

    def block_ip_in_container(self, container_id: str, src_ip: str) -> tuple[int, str]:
        """
        Insert an iptables DROP rule for src_ip inside the container.
        Uses the existing iptables binary already in the container.
        """
        cmd = f"iptables -I INPUT -s {src_ip} -j DROP"
        return self.exec_command(container_id, cmd)

    def unblock_ip_in_container(self, container_id: str, src_ip: str) -> tuple[int, str]:
        """Remove the iptables DROP rule for src_ip (rollback)."""
        cmd = f"iptables -D INPUT -s {src_ip} -j DROP"
        return self.exec_command(container_id, cmd)

    def block_outbound_ip(self, container_id: str, dst_ip: str) -> tuple[int, str]:
        """Block outbound traffic to a C2 destination IP."""
        cmd = f"iptables -I OUTPUT -d {dst_ip} -j DROP"
        return self.exec_command(container_id, cmd)

    def lock_user_account(self, container_id: str, username: str) -> tuple[int, str]:
        """Disable a user account with usermod -L."""
        cmd = f"usermod -L {username}"
        return self.exec_command(container_id, cmd)

    def unlock_user_account(self, container_id: str, username: str) -> tuple[int, str]:
        """Re-enable a user account (rollback)."""
        cmd = f"usermod -U {username}"
        return self.exec_command(container_id, cmd)

    def capture_pcap(
        self,
        container_id: str,
        interface: str = "eth0",
        duration: int = 30,
        output_path: str = "/tmp/capture.pcap",
    ) -> tuple[int, str]:
        """Run tcpdump inside the container for forensics."""
        cmd = f"timeout {duration} tcpdump -i {interface} -w {output_path} &"
        return self.exec_command(container_id, cmd)

    def get_container_info(self, container_id: str) -> dict[str, Any]:
        """Return basic info about a container."""
        if not self._client:
            return {}
        try:
            container = self._client.containers.get(container_id)
            return {
                "id": container.short_id,
                "name": container.name,
                "status": container.status,
                "networks": list(container.attrs.get("NetworkSettings", {}).get("Networks", {}).keys()),
            }
        except Exception:  # noqa: BLE001
            return {}

    def find_container_by_ip(self, ip_address: str) -> str | None:
        """
        Try to find a container whose network IP matches ip_address.
        Returns the container name, or None if not found.
        """
        if not self._client:
            return None
        try:
            for container in self._client.containers.list():
                nets = container.attrs.get("NetworkSettings", {}).get("Networks", {})
                for net_info in nets.values():
                    if net_info.get("IPAddress") == ip_address:
                        return container.name
        except Exception:  # noqa: BLE001
            pass
        return None
