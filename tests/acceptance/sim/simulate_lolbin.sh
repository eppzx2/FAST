#!/bin/bash
# ============================================================
# Simulate: wget Masquerading as httpd (triggers Wazuh rules
# 100220 -> 100221)
# ============================================================
# Copies the wget binary to /tmp/httpd (so the process name/comm
# becomes "httpd") and executes it with wget-style arguments
# against a harmless local URL, to trigger the LOLBin masquerading
# detection.
#
# IMPORTANT: this script must run ON THE TARGET HOST itself (the
# machine whose Wazuh Agent + auditd are being tested), not remotely -
# auditd only sees local process execution.
#
# REQUIREMENT: auditd must be installed and watching execve on this
# host - see setup_prereqs.sh.
#
# USAGE (on the target host):
#   ./simulate_lolbin.sh
# ============================================================

set -Eeuo pipefail

WGET_BIN="$(command -v wget || true)"
if [ -z "$WGET_BIN" ]; then
    echo "ERROR: wget is not installed on this host." >&2
    exit 1
fi

FAKE_HTTPD="/tmp/httpd"

echo "==> Copying $WGET_BIN to $FAKE_HTTPD (masquerading as httpd)"
cp "$WGET_BIN" "$FAKE_HTTPD"
chmod +x "$FAKE_HTTPD"

echo "==> Executing $FAKE_HTTPD with wget-style arguments"
# A harmless, always-resolvable target; -T sets a short timeout so
# this does not hang if outbound network is restricted. We don't
# care whether the request itself succeeds - only that the process
# executes and auditd captures the EXECVE event.
"$FAKE_HTTPD" -T 3 -t 1 -O /tmp/httpd_sim_output.tmp "http://example.com/" >/dev/null 2>&1 || true

rm -f /tmp/httpd_sim_output.tmp "$FAKE_HTTPD"

echo "[OK] Simulated masquerading process executed. Rules 100220/100221 should fire within 60s."
