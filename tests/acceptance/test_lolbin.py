"""
Acceptance test: wget masquerading as httpd (LOLBin) -> Wazuh rule
100221.

auditd only observes LOCAL process execution, so the simulation
script must run ON the target host itself. This test runs it
remotely over SSH (key-based auth required - see
tests/acceptance/sim/setup_prereqs.sh for the auditd prerequisite).

Skips (does not fail) if TARGET_HOST is not set, or if the Wazuh
Manager isn't running (see conftest.py).
"""

import os
import subprocess
from pathlib import Path

import pytest

RULE_ID = 100221
SIM_SCRIPT = Path(__file__).parent / "sim" / "simulate_lolbin.sh"


def test_wget_masquerading_as_httpd_triggers_rule_100221(alert_line_count, wait_for_rule_alert):
    target_host = os.environ.get("TARGET_HOST")
    if not target_host:
        pytest.skip(
            "TARGET_HOST env var not set - point it at a host with a "
            "Wazuh agent, auditd, and SSH key-based access, "
            "e.g. TARGET_HOST=1.2.3.4"
        )

    ssh_user = os.environ.get("TARGET_SSH_USER", "root")

    since_line = alert_line_count()

    script_content = SIM_SCRIPT.read_text()

    result = subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5",
         f"{ssh_user}@{target_host}", "bash -s"],
        input=script_content, capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, (
        f"Remote execution of simulate_lolbin.sh on {target_host} failed:\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}\n"
        f"(requires SSH key-based access as {ssh_user}@{target_host}, and "
        f"auditd installed/configured - see tests/acceptance/sim/setup_prereqs.sh)"
    )

    alert = wait_for_rule_alert(RULE_ID, since_line, timeout=60)

    assert alert is not None, (
        f"Rule {RULE_ID} (LOLBin masquerading) did not fire within 60 seconds. "
        f"Check that auditd is running and watching execve on {target_host} "
        f"(see setup_prereqs.sh), and that the agent collects "
        f"/var/log/audit/audit.log."
    )
    assert int(alert["rule"]["level"]) >= 6, (
        f"Rule {RULE_ID} fired but at an unexpectedly low level: {alert['rule']}"
    )
