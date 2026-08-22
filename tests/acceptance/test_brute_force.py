"""
Acceptance test: SSH brute force -> Wazuh rule 100200.

Requires TARGET_HOST (a host with a Wazuh agent reporting to the
Manager). Skips (does not fail) if TARGET_HOST is not set, or if the
Wazuh Manager isn't running (see conftest.py).
"""

import os
import subprocess
from pathlib import Path

import pytest

RULE_ID = 100200
SIM_SCRIPT = Path(__file__).parent / "sim" / "simulate_brute_force.sh"


def test_ssh_brute_force_triggers_rule_100200(alert_line_count, wait_for_rule_alert):
    target_host = os.environ.get("TARGET_HOST")
    if not target_host:
        pytest.skip(
            "TARGET_HOST env var not set - point it at a host with a "
            "Wazuh agent reachable over SSH, e.g. TARGET_HOST=1.2.3.4"
        )

    ssh_user = os.environ.get("BRUTE_FORCE_SSH_USER", "nonexistent_bruteforce_test_user")

    since_line = alert_line_count()

    result = subprocess.run(
        ["bash", str(SIM_SCRIPT), target_host, ssh_user, "5"],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, (
        f"simulate_brute_force.sh failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )

    alert = wait_for_rule_alert(RULE_ID, since_line, timeout=60)

    assert alert is not None, (
        f"Rule {RULE_ID} (SSH brute force) did not fire within 60 seconds. "
        f"Check that sshd authentication logs reach the Manager (Wazuh's default "
        f"journald collection covers this) and that base rule 5716 is loaded "
        f"(grep -r 'id=\"5716\"' inside the wazuh-manager container's ruleset)."
    )
    assert int(alert["rule"]["level"]) >= 5, (
        f"Rule {RULE_ID} fired but at an unexpectedly low level: {alert['rule']}"
    )
