"""
Acceptance test: Nmap-style port scan -> Wazuh rule 100211.

Requires TARGET_HOST with UFW (or another logged firewall) enabled -
see tests/acceptance/sim/setup_prereqs.sh. Skips (does not fail) if
TARGET_HOST is not set, or if the Wazuh Manager isn't running (see
conftest.py).
"""

import os
import subprocess
from pathlib import Path

import pytest

RULE_ID = 100211
SIM_SCRIPT = Path(__file__).parent / "sim" / "simulate_port_scan.sh"


def test_port_scan_triggers_rule_100211(alert_line_count, wait_for_rule_alert):
    target_host = os.environ.get("TARGET_HOST")
    if not target_host:
        pytest.skip(
            "TARGET_HOST env var not set - point it at a host with a "
            "Wazuh agent and firewall logging enabled, e.g. TARGET_HOST=1.2.3.4"
        )

    since_line = alert_line_count()

    result = subprocess.run(
        ["bash", str(SIM_SCRIPT), target_host],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, (
        f"simulate_port_scan.sh failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )

    alert = wait_for_rule_alert(RULE_ID, since_line, timeout=60)

    assert alert is not None, (
        f"Rule {RULE_ID} (port scan) did not fire within 60 seconds. "
        f"Check that UFW/firewall logging is enabled on {target_host} "
        f"(run tests/acceptance/sim/setup_prereqs.sh on the target first) "
        f"and that base rule 4100 is loaded on the Manager."
    )
    assert int(alert["rule"]["level"]) >= 5, (
        f"Rule {RULE_ID} fired but at an unexpectedly low level: {alert['rule']}"
    )
