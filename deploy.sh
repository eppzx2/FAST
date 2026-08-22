#!/bin/bash
# ============================================================
# F.A.S.T. - OSINT Threat Aggregation + Wazuh SIEM
# Single-Script Fast Deployment
# ============================================================
#
# This script does the following:
#   1. Downloads the official Wazuh Docker stack (Manager+Indexer+Dashboard)
#      (first run only - this step is skipped on later runs)
#   2. Generates certificates (first run only)
#   3. Starts the Wazuh stack with a FULLY DEFAULT configuration
#   4. Verifies the Manager started up healthy (authd/analysisd/remoted)
#   5. Copies in the custom detection rule via `docker cp`
#   6. Builds the IOC Collector image and runs the first collection
#   7. Copies in the CDB list via `docker cp` and restarts the Manager
#
#
# REQUIREMENTS: Docker + Docker Compose plugin must be installed
#
# USAGE: ./deploy.sh [--ip <MANAGER_IP>]
#   --ip <IP>   Manually set the Manager's IP (to display for agents).
#               If not provided, it's auto-detected: first the Tailscale
#               IP, if not found the public IP, if not found the local IP.
# TO REFRESH (only update IOCs): ./refresh_iocs.sh
# ============================================================

set -e

# --- Parse parameters ---
MANAGER_IP_OVERRIDE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ip|-i)
            MANAGER_IP_OVERRIDE="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: ./deploy.sh [--ip <MANAGER_IP>]"
            echo ""
            echo "  --ip <IP>   Manually set the Manager's IP."
            echo "              If not provided, it's auto-detected."
            exit 0
            ;;
        *)
            echo "✗ Unknown parameter: $1 (see: ./deploy.sh --help)"
            exit 1
            ;;
    esac
done

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WAZUH_DIR="$PROJECT_ROOT/wazuh-docker"
WAZUH_VERSION="v4.9.0"
MANAGER_CONTAINER="single-node-wazuh.manager-1"
HEALTH_CHECK_TIMEOUT=180   # seconds
HEALTH_CHECK_INTERVAL=10   # seconds

echo "════════════════════════════════════════════════════════"
echo "  F.A.S.T. - Deployment Starting"
echo "════════════════════════════════════════════════════════"

# --- Prerequisite checks ---
command -v docker >/dev/null 2>&1 || { echo "✗ Docker is not installed. Install it: https://docs.docker.com/engine/install/"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "✗ Docker Compose plugin not found."; exit 1; }
command -v git >/dev/null 2>&1 || { echo "✗ Git is not installed."; exit 1; }

echo "✓ Docker, Docker Compose, Git are available"
echo ""

# --- Helper function: finds an IP that can be used to connect to the Manager ---
# Order: 1) value given via --ip, 2) Tailscale IP (if present), 3) public IP, 4) local IP
_is_valid_ipv4() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS='.'
    local -a octets=($ip)
    for octet in "${octets[@]}"; do
        [ "$octet" -le 255 ] || return 1
    done
    return 0
}

detect_manager_ip() {
    if [ -n "$MANAGER_IP_OVERRIDE" ]; then
        echo "$MANAGER_IP_OVERRIDE"
        return
    fi

    if command -v tailscale >/dev/null 2>&1; then
        local ts_ip
        ts_ip=$(tailscale ip -4 2>/dev/null | head -1)
        if _is_valid_ipv4 "$ts_ip"; then
            echo "$ts_ip"
            return
        fi
    fi

    local pub_ip
    pub_ip=$(curl -sf --max-time 5 https://ifconfig.me 2>/dev/null)
    if _is_valid_ipv4 "$pub_ip"; then
        echo "$pub_ip"
        return
    fi

    local local_ip
    local_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    if _is_valid_ipv4 "$local_ip"; then
        echo "$local_ip"
        return
    fi

    # None found - return empty, the caller handles this
    echo ""
}

# --- Helper function: checks whether the Manager is healthy ---
# Healthy = the wazuh-authd, wazuh-analysisd, wazuh-remoted processes
# are ALL running AND there are no CRITICAL errors in the logs.
wait_for_manager_healthy() {
    local elapsed=0
    echo "🔍 Checking Manager health..."

    while [ "$elapsed" -lt "$HEALTH_CHECK_TIMEOUT" ]; do
        local critical_errors
        critical_errors=$(docker logs "$MANAGER_CONTAINER" 2>&1 | grep -c "CRITICAL" || true)

        local proc_count
        proc_count=$(docker exec "$MANAGER_CONTAINER" ps aux 2>/dev/null | grep -cE "wazuh-authd|wazuh-analysisd|wazuh-remoted" || true)

        if [ "$critical_errors" -eq 0 ] && [ "$proc_count" -ge 3 ]; then
            echo "✓ Manager is healthy (authd, analysisd, remoted running, no errors)"
            return 0
        fi

        sleep "$HEALTH_CHECK_INTERVAL"
        elapsed=$((elapsed + HEALTH_CHECK_INTERVAL))
        echo "  ... waiting (${elapsed}s/${HEALTH_CHECK_TIMEOUT}s)"
    done

    echo "✗ ERROR: Manager did not become healthy within ${HEALTH_CHECK_TIMEOUT} seconds."
    echo "  For diagnostics: docker logs $MANAGER_CONTAINER | grep -i error"
    return 1
}

# --- STEP 1: Wazuh Docker Repo ---
if [ ! -d "$WAZUH_DIR" ]; then
    echo "📥 Downloading the Wazuh Docker stack ($WAZUH_VERSION)..."
    git clone --branch "$WAZUH_VERSION" --depth 1 https://github.com/wazuh/wazuh-docker.git "$WAZUH_DIR"
else
    echo "✓ Wazuh Docker stack already exists ($WAZUH_DIR)"
fi

cd "$WAZUH_DIR/single-node"

# --- STEP 2: Certificates ---
if [ ! -d "config/wazuh_indexer_ssl_certs" ] || [ -z "$(ls -A config/wazuh_indexer_ssl_certs 2>/dev/null)" ]; then
    echo ""
    echo "🔐 Generating SSL certificates..."
    docker compose -f generate-indexer-certs.yml run --rm generator
else
    echo "✓ Certificates already exist"
fi

# If an old override file is still present (from a previous version), remove
# it - to avoid bind-mount issues. See the NOTE at the top of the file.
if [ -f "./docker-compose.override.yml" ]; then
    echo "⚠️  Old docker-compose.override.yml found, removing it..."
    rm -f ./docker-compose.override.yml
fi

# --- STEP 3: Starting the Wazuh Stack with a FULLY DEFAULT Configuration ---
echo ""
echo "🚀 Starting Wazuh Manager + Indexer + Dashboard..."
docker compose up -d

echo ""
echo "⏳ Waiting for containers to start (30 seconds)..."
sleep 30

# --- STEP 4: Health Check (BEFORE copying in Rules/List) ---
if ! wait_for_manager_healthy; then
    echo "✗ Deployment stopped - the Manager did not start up healthy."
    exit 1
fi

# --- STEP 5: Copying in the Custom Detection Rule via docker cp ---
echo ""
echo "🔗 Applying the TALON IOC Collector detection rule..."
docker cp "$PROJECT_ROOT/docker/rules/local_rules.xml" "${MANAGER_CONTAINER}:/var/ossec/etc/rules/local_rules.xml"
docker restart "$MANAGER_CONTAINER" >/dev/null

echo "⏳ Rechecking health after the restart..."
sleep 20
if ! wait_for_manager_healthy; then
    echo "✗ Deployment stopped - the Manager did not start up healthy after the custom rule."
    exit 1
fi

# --- STEP 6: IOC Collector - Build + First Collection ---
echo ""
echo "════════════════════════════════════════════════════════"
echo "  TALON IOC Collector - First Collection"
echo "════════════════════════════════════════════════════════"
cd "$PROJECT_ROOT"

echo "🔨 Building the IOC Collector image..."
docker build -t osint-ioc-collector -f docker/ioc-collector.Dockerfile .

echo ""
echo "📡 Collecting from feeds, normalizing, exporting to Wazuh CDB..."
docker run --rm -v "$PROJECT_ROOT:/app" osint-ioc-collector \
    --init-db --fetch --export wazuh

# --- STEP 7: Copying in the CDB List via docker cp ---
echo ""
echo "🔄 Copying the CDB list to the Wazuh Manager and applying it..."
docker cp "$PROJECT_ROOT/sample_output/ioc-ips" "${MANAGER_CONTAINER}:/var/ossec/etc/lists/ioc-ips"
docker restart "$MANAGER_CONTAINER" >/dev/null

echo "⏳ Checking health after the final restart..."
sleep 20
if ! wait_for_manager_healthy; then
    echo "✗ WARNING: The Manager does not appear healthy after copying in the CDB list."
    echo "  Diagnostics: docker logs $MANAGER_CONTAINER | grep -i error"
    echo "  (The Dashboard may still work, but check the detection rules)"
fi

echo ""
echo "════════════════════════════════════════════════════════"
echo "  ✅ DEPLOYMENT COMPLETE"
echo "════════════════════════════════════════════════════════"

DETECTED_IP=$(detect_manager_ip)

echo ""
echo "Wazuh Dashboard:  https://${DETECTED_IP:-localhost}"
echo "  Username: admin"
echo "  Password: SecretPassword (change it on first login!)"
echo ""

if [ -n "$DETECTED_IP" ]; then
    echo "────────────────────────────────────────────────────────"
    echo "  Manager IP for Agent Connection: $DETECTED_IP"
    echo "────────────────────────────────────────────────────────"
    echo ""
    echo "To connect from a Windows host (PowerShell, Administrator):"
    echo "  cd windows"
    echo "  .\\install-wazuh-agent.ps1 -ManagerIP \"$DETECTED_IP\""
    echo ""
    echo "To connect from a Linux target:"
    echo "  cd linux"
    echo "  sudo ./install-wazuh-agent.sh --ip $DETECTED_IP"
else
    echo "⚠️  The Manager IP could not be auto-detected."
    echo "   Set it manually next time: ./deploy.sh --ip <IP_ADDRESS>"
    echo ""
fi

echo "To refresh IOCs: ./refresh_iocs.sh"
echo "To stop the stack: cd wazuh-docker/single-node && docker compose down"
