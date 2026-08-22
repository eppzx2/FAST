#!/bin/bash
# ============================================================
# Acceptance Test Prerequisites Setup
# ============================================================
# Run this ONCE, as root, on the TARGET host (the machine running
# the Wazuh Agent that the simulation scripts will attack/exercise -
# NOT on the Wazuh Manager).
#
# It prepares the two detections that need extra log sources beyond
# what the agent collects by default (SSH brute force needs nothing
# extra - journald already covers it):
#
#   1. Port scan detection  -> enables UFW + connection logging
#   2. LOLBin detection     -> installs auditd + an execve watch rule
#
# Idempotent: safe to run more than once.
#
# USAGE: sudo ./setup_prereqs.sh
# ============================================================

set -Eeuo pipefail

if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root (sudo ./setup_prereqs.sh)." >&2
    exit 1
fi

echo "==> [1/2] Enabling UFW with connection logging (for port-scan detection)..."
if ! command -v ufw >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y ufw
fi
ufw logging on
# Allow SSH first so we don't lock ourselves out, then enable.
ufw allow OpenSSH >/dev/null 2>&1 || true
yes | ufw enable
echo "[OK] UFW enabled with logging (blocked connections will appear in journald)"

echo ""
echo "==> [2/2] Installing and configuring auditd (for LOLBin detection)..."
if ! command -v auditctl >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y auditd audispd-plugins
fi

AUDIT_RULE_FILE="/etc/audit/rules.d/wazuh-execve.rules"
if [ ! -f "$AUDIT_RULE_FILE" ] || ! grep -q "audit-wazuh-c" "$AUDIT_RULE_FILE" 2>/dev/null; then
    cat > "$AUDIT_RULE_FILE" << 'EOF'
-a always,exit -F arch=b64 -S execve -k audit-wazuh-c
-a always,exit -F arch=b32 -S execve -k audit-wazuh-c
EOF
    augenrules --load 2>/dev/null || auditctl -R "$AUDIT_RULE_FILE"
fi
systemctl enable auditd >/dev/null 2>&1 || true
systemctl restart auditd
echo "[OK] auditd installed and watching execve syscalls (key=audit-wazuh-c)"

echo ""
echo "==> Checking that the Wazuh agent collects /var/log/audit/audit.log..."
OSSEC_CONF="/var/ossec/etc/ossec.conf"
if [ -f "$OSSEC_CONF" ] && ! grep -q "/var/log/audit/audit.log" "$OSSEC_CONF"; then
    echo "[!] The Wazuh agent config does not yet monitor /var/log/audit/audit.log."
    echo "    Add this block inside <ossec_config> in $OSSEC_CONF, then restart the agent:"
    echo ""
    echo "      <localfile>"
    echo "        <log_format>audit</log_format>"
    echo "        <location>/var/log/audit/audit.log</location>"
    echo "      </localfile>"
    echo ""
    echo "    sudo systemctl restart wazuh-agent"
else
    echo "[OK] Wazuh agent already configured to collect audit.log (or ossec.conf not found on this host)"
fi

echo ""
echo "Prerequisites setup complete."
