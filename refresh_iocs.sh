#!/bin/bash
# ============================================================
# F.A.S.T. - IOC Refresh Script
# ============================================================
# Without repeating deploy.sh's full setup steps, this only
# re-collects IOCs and pushes them to Wazuh.
#
# Usage: ./refresh_iocs.sh
# Example for cron (every day at 03:00):
#   0 3 * * * /path/to/osint-ioc-collector/refresh_iocs.sh >> /var/log/fast-refresh.log 2>&1
# ============================================================
set -e
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANAGER_CONTAINER="single-node-wazuh.manager-1"
echo "===== $(date -u +%Y-%m-%dT%H:%M:%SZ) - IOC refresh started ====="
cd "$PROJECT_ROOT"
docker run --rm -v "$PROJECT_ROOT:/app" osint-ioc-collector \
    --fetch --export wazuh
docker cp "$PROJECT_ROOT/sample_output/ioc-ips" "${MANAGER_CONTAINER}:/var/ossec/etc/lists/ioc-ips"
docker restart "$MANAGER_CONTAINER" >/dev/null
echo "⏳ Checking health after the restart (20 seconds)..."
sleep 20
critical_errors=$(docker logs "$MANAGER_CONTAINER" --since 30s 2>&1 | grep -c "CRITICAL" || true)
proc_count=$(docker exec "$MANAGER_CONTAINER" ps aux 2>/dev/null | grep -cE "wazuh-authd|wazuh-analysisd|wazuh-remoted" || true)
if [ "$critical_errors" -eq 0 ] && [ "$proc_count" -ge 3 ]; then
    echo "✓ Manager is healthy"
else
    echo "⚠️  WARNING: The Manager does not appear healthy after the restart."
    echo "   Diagnostics: docker logs $MANAGER_CONTAINER | grep -i error"
fi
echo "===== $(date -u +%Y-%m-%dT%H:%M:%SZ) - IOC refresh complete ====="
