"""
playbook_scripts/network/block_c2_ip.py
-----------------------------------------
ACT-008 — Block C2 Destination IP

Blocks outbound traffic from the IoT container to a known C2 server
by inserting an iptables OUTPUT DROP rule inside the container.
Used for malware_or_c2 and dns_suspicious playbooks.
"""

from __future__ import annotations

from typing import Any

from playbook_scripts.base_script import BaseScript, ScriptResult


class BlockC2IPScript(BaseScript):
    SCRIPT_NAME = "block_c2_ip"
    ACTION_CLASS = "network_containment"

    def execute(self, context: dict[str, Any]) -> ScriptResult:
        dst_ip       = self._get(context, "destination_ip")
        container_id = self._get(context, "container_id")

        if not dst_ip or dst_ip == "unknown":
            return ScriptResult(success=False, output="destination_ip not available in context")

        self._log_action("Blocking C2 destination IP", dst_ip=dst_ip, container=container_id)

        exit_code, output = self.docker.block_outbound_ip(container_id, dst_ip)
        success = exit_code == 0

        if success:
            self._log_action("C2 IP blocked", dst_ip=dst_ip)
        else:
            self._log_error("Failed to block C2 IP", dst_ip=dst_ip, output=output)

        return ScriptResult(
            success=success,
            exit_code=exit_code,
            output=output,
            rollback_fn="rollback",
            metadata={"blocked_c2_ip": dst_ip, "container": container_id},
        )

    def rollback(self, context: dict[str, Any]) -> ScriptResult:
        dst_ip       = self._get(context, "destination_ip")
        container_id = self._get(context, "container_id")
        self._log_action("Rolling back — unblocking C2 IP", dst_ip=dst_ip)
        cmd = f"iptables -D OUTPUT -d {dst_ip} -j DROP"
        exit_code, output = self.docker.exec_command(container_id, cmd)
        return ScriptResult(success=exit_code == 0, exit_code=exit_code, output=output)


class BlockDNSEgressScript(BaseScript):
    """
    ACT-013 — Block DNS Egress from Host
    Prevents the container from sending DNS queries to external resolvers.
    Used for dns_suspicious playbooks (tunneling, DGA, .onion queries).
    """
    SCRIPT_NAME = "block_dns_egress"
    ACTION_CLASS = "network_containment"

    def execute(self, context: dict[str, Any]) -> ScriptResult:
        container_id = self._get(context, "container_id")
        # Block outbound UDP/TCP port 53 to any external resolver
        cmd = "iptables -I OUTPUT -p udp --dport 53 -j DROP && iptables -I OUTPUT -p tcp --dport 53 -j DROP"
        self._log_action("Blocking DNS egress", container=container_id)
        exit_code, output = self.docker.exec_command(container_id, cmd)
        return ScriptResult(
            success=exit_code == 0,
            exit_code=exit_code,
            output=output,
            rollback_fn="rollback",
            metadata={"container": container_id},
        )

    def rollback(self, context: dict[str, Any]) -> ScriptResult:
        container_id = self._get(context, "container_id")
        cmd = "iptables -D OUTPUT -p udp --dport 53 -j DROP; iptables -D OUTPUT -p tcp --dport 53 -j DROP"
        exit_code, output = self.docker.exec_command(container_id, cmd)
        return ScriptResult(success=exit_code == 0, exit_code=exit_code, output=output)


class RateLimitIPScript(BaseScript):
    """
    ACT-002 — Rate-Limit Source IP Traffic
    Applies iptables rate limiting (hashlimit) to throttle a scanning/flooding IP.
    """
    SCRIPT_NAME = "rate_limit_ip"
    ACTION_CLASS = "network_mitigation"

    def execute(self, context: dict[str, Any]) -> ScriptResult:
        src_ip       = self._get(context, "source_ip")
        container_id = self._get(context, "container_id")
        # Allow max 10 packets per minute from this IP, burst 20
        cmd = (
            f"iptables -I INPUT -s {src_ip} -m hashlimit "
            f"--hashlimit-mode srcip --hashlimit-above 10/min "
            f"--hashlimit-burst 20 --hashlimit-name ratelimit_{src_ip.replace('.','_')} "
            f"-j DROP"
        )
        self._log_action("Rate-limiting source IP", src_ip=src_ip, container=container_id)
        exit_code, output = self.docker.exec_command(container_id, cmd)
        return ScriptResult(
            success=exit_code == 0,
            exit_code=exit_code,
            output=output,
            rollback_fn="rollback",
            metadata={"rate_limited_ip": src_ip},
        )

    def rollback(self, context: dict[str, Any]) -> ScriptResult:
        src_ip       = self._get(context, "source_ip")
        container_id = self._get(context, "container_id")
        name = f"ratelimit_{src_ip.replace('.','_')}"
        cmd  = f"iptables -D INPUT -s {src_ip} -m hashlimit --hashlimit-name {name} -j DROP"
        exit_code, output = self.docker.exec_command(container_id, cmd)
        return ScriptResult(success=exit_code == 0, exit_code=exit_code, output=output)
