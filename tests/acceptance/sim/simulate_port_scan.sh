#!/bin/bash
# ============================================================
# Simulate: Nmap Port Scan (triggers Wazuh rule 100211)
# ============================================================
# Sends connection attempts to 8+ likely-closed ports on the target
# within a short window, to trigger the frequency-based port-scan
# rule (8 blocked/refused attempts / 60s / same_source_ip).
#
# Uses `nmap -sS` if available (fast SYN scan); falls back to a
# pure-bash /dev/tcp loop otherwise (slower but requires no
# extra tooling).
#
# REQUIREMENT: the TARGET_HOST must have UFW (or another logged
# firewall) enabled with logging on - see setup_prereqs.sh.
#
# USAGE:
#   ./simulate_port_scan.sh <target_host>
# ============================================================

set -Eeuo pipefail

TARGET_HOST="${1:?Usage: $0 <target_host>}"
# A spread of likely-closed, non-service ports.
PORTS=(1234 4321 5555 6666 7777 8888 9999 31337 12345)

echo "==> Simulating port scan against $TARGET_HOST (${#PORTS[@]} ports)"

if command -v nmap >/dev/null 2>&1; then
    PORT_LIST=$(IFS=,; echo "${PORTS[*]}")
    nmap -sS -Pn -T4 -p "$PORT_LIST" "$TARGET_HOST" >/dev/null 2>&1 || true
    echo "[OK] nmap SYN scan sent to ports: $PORT_LIST"
else
    echo "  (nmap not found, using bash /dev/tcp fallback)"
    for port in "${PORTS[@]}"; do
        timeout 1 bash -c "echo >/dev/tcp/${TARGET_HOST}/${port}" 2>/dev/null || true
        echo "  probed port $port"
    done
    echo "[OK] Probed ${#PORTS[@]} ports via /dev/tcp"
fi

echo "Rule 100211 should fire within 60s (requires UFW/firewall logging enabled on the target - see setup_prereqs.sh)."
