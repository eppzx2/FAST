#!/bin/bash
# ============================================================
# Simulate: SSH Brute Force (triggers Wazuh rule 100200)
# ============================================================
# Attempts 5 SSH logins with a wrong password against the target
# host within a few seconds, from the same source, to trigger the
# frequency-based brute-force rule (5 attempts / 60s / same_source_ip).
#
# REQUIREMENTS: sshpass installed on the machine running this script;
# the TARGET_HOST must have a Wazuh agent reporting to the Manager.
#
# USAGE:
#   ./simulate_brute_force.sh <target_host> [ssh_user] [attempts]
#
# Example:
#   ./simulate_brute_force.sh 100.87.195.65 testuser 5
# ============================================================

set -Eeuo pipefail

TARGET_HOST="${1:?Usage: $0 <target_host> [ssh_user] [attempts]}"
SSH_USER="${2:-nonexistent_bruteforce_test_user}"
ATTEMPTS="${3:-5}"

command -v sshpass >/dev/null 2>&1 || {
    echo "ERROR: sshpass is required. Install with: sudo apt-get install -y sshpass" >&2
    exit 1
}

echo "==> Simulating SSH brute force against $TARGET_HOST ($ATTEMPTS attempts, user=$SSH_USER)"

for i in $(seq 1 "$ATTEMPTS"); do
    sshpass -p "definitely-wrong-password-$RANDOM" \
        ssh -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=5 \
            -o PasswordAuthentication=yes \
            -o PreferredAuthentications=password \
            "${SSH_USER}@${TARGET_HOST}" "true" 2>/dev/null || true
    echo "  attempt $i/$ATTEMPTS sent"
done

echo "[OK] Sent $ATTEMPTS failed SSH login attempts. Rule 100200 should fire within 60s."
