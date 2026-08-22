"""
Shared fixtures for FAST acceptance tests.

These tests exercise a REAL, deployed FAST/Wazuh environment (unlike
the unit tests in tests/, which are fully mocked and offline). They
are automatically skipped - not failed - when the Wazuh Manager
container isn't running, so `pytest tests/` at the repo root still
works the same as before for CI / offline development.

Required environment for a full run:
    TARGET_HOST              - host with a Wazuh agent, used by the
                                brute-force / port-scan / LOLBin sims
    WAZUH_MANAGER_CONTAINER  - defaults to "single-node-wazuh.manager-1"
                                (matches deploy.sh / bin/fast)
"""

import json
import os
import shutil
import subprocess
import time

import pytest

MANAGER_CONTAINER = os.environ.get("WAZUH_MANAGER_CONTAINER", "single-node-wazuh.manager-1")
ALERTS_PATH = "/var/ossec/logs/alerts/alerts.json"


def _manager_running() -> bool:
    if shutil.which("docker") is None:
        return False
    result = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Status}}", MANAGER_CONTAINER],
        capture_output=True, text=True,
    )
    return result.returncode == 0 and result.stdout.strip() == "running"


@pytest.fixture(scope="session", autouse=True)
def require_manager():
    """Skips all acceptance tests if the Wazuh Manager isn't up."""
    if not _manager_running():
        pytest.skip(
            f"Wazuh Manager container '{MANAGER_CONTAINER}' is not running. "
            f"Deploy FAST first (./bin/fast up) before running acceptance tests."
        )


@pytest.fixture
def alert_line_count():
    """
    Returns a callable that reports the current line count of
    alerts.json inside the Manager container. Used to mark "only
    look at alerts appended after this point" before running a
    simulation, so tests don't match stale alerts from earlier runs.
    """
    def _get() -> int:
        result = subprocess.run(
            ["docker", "exec", MANAGER_CONTAINER, "sh", "-c",
             f"wc -l < {ALERTS_PATH} 2>/dev/null || echo 0"],
            capture_output=True, text=True,
        )
        try:
            return int(result.stdout.strip() or 0)
        except ValueError:
            return 0
    return _get


@pytest.fixture
def wait_for_rule_alert():
    """
    Returns a callable: wait_for_rule_alert(rule_id, since_line, timeout=60)
    Polls the Manager's alerts.json for a NEW alert (appended after
    `since_line`) matching `rule_id`. Returns the parsed alert dict,
    or None if it did not appear within `timeout` seconds.
    """
    def _wait(rule_id, since_line: int, timeout: int = 60, poll_interval: int = 2):
        deadline = time.time() + timeout
        rule_id_str = str(rule_id)

        while time.time() < deadline:
            result = subprocess.run(
                ["docker", "exec", MANAGER_CONTAINER, "sh", "-c",
                 f"tail -n +{since_line + 1} {ALERTS_PATH} 2>/dev/null"],
                capture_output=True, text=True,
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    alert = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if str(alert.get("rule", {}).get("id")) == rule_id_str:
                    return alert
            time.sleep(poll_interval)

        return None
    return _wait
