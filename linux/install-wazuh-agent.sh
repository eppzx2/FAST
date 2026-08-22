#!/bin/bash
# ============================================================
# F.A.S.T. - Linux Wazuh Agent Automated Installation
# ============================================================
#
# This script downloads the Wazuh Agent on a Linux host machine,
# installs it, configures it to connect to the Manager (the cloud
# VM), and starts the service.
#
# Supported distros:
#   - Ubuntu / Debian (apt)
#   - CentOS / RHEL / Fedora (yum/dnf)
#
# USAGE:
#   sudo ./install-wazuh-agent.sh --ip <MANAGER_IP>
#   sudo ./install-wazuh-agent.sh --ip 1.12.1.12
#
# Optional:
#   sudo ./install-wazuh-agent.sh --ip 1.12.1.12 --name "my-server"
# ============================================================

set -e

WAZUH_VERSION="4.9.0"
MANAGER_IP=""
AGENT_NAME="$(hostname)"

# --- Colored output ---
GREEN="\033[0;32m"
CYAN="\033[0;36m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
NC="\033[0m"

step()    { echo -e "\n${CYAN}==> $1${NC}"; }
success() { echo -e "${GREEN}[OK] $1${NC}"; }
warn()    { echo -e "${YELLOW}[!]  $1${NC}"; }
fail()    { echo -e "${RED}[ERROR] $1${NC}"; exit 1; }

# --- Parse parameters ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ip|-i)
            MANAGER_IP="$2"
            shift 2
            ;;
        --name|-n)
            AGENT_NAME="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: sudo $0 --ip <MANAGER_IP> [--name <AGENT_NAME>]"
            echo ""
            echo "  --ip   <IP>    Wazuh Manager's IP address (required)"
            echo "  --name <NAME>  Name to give the agent (default: hostname)"
            echo ""
            echo "Example:"
            echo "  sudo $0 --ip 1.12.1.12"
            echo "  sudo $0 --ip 1.12.1.12 --name agent-ubuntu"
            exit 0
            ;;
        *)
            fail "Unknown parameter: $1  (see: $0 --help)"
            ;;
    esac
done

# --- Required parameter check ---
if [ -z "$MANAGER_IP" ]; then
    echo -e "${RED}Error: the --ip parameter is required.${NC}"
    echo ""
    echo "Usage: sudo $0 --ip <MANAGER_IP>"
    echo "Example: sudo $0 --ip 1.12.1.12"
    exit 1
fi

# --- Root check ---
if [ "$EUID" -ne 0 ]; then
    fail "This script requires root privileges. Run it with 'sudo ./install-wazuh-agent.sh ...'."
fi

echo ""
echo "============================================================"
echo -e "  ${CYAN}F.A.S.T. - Linux Wazuh Agent Installation${NC}"
echo "============================================================"
echo "Manager IP  : $MANAGER_IP"
echo "Agent Name  : $AGENT_NAME"
echo "Version     : $WAZUH_VERSION"

# --- Detect package manager ---
step "Detecting package manager..."
if command -v apt-get >/dev/null 2>&1; then
    PKG_MANAGER="apt"
    success "apt detected (Ubuntu/Debian)"
elif command -v dnf >/dev/null 2>&1; then
    PKG_MANAGER="dnf"
    success "dnf detected (Fedora/RHEL 8+)"
elif command -v yum >/dev/null 2>&1; then
    PKG_MANAGER="yum"
    success "yum detected (CentOS/RHEL)"
else
    fail "No supported package manager found (apt/dnf/yum required)"
fi

# --- Check that the Manager IP is reachable ---
step "Checking Manager reachability ($MANAGER_IP)..."
ALL_PORTS_OK=true
for port in 1514 1515; do
    if timeout 5 bash -c ">/dev/tcp/$MANAGER_IP/$port" 2>/dev/null; then
        success "Port $port is reachable"
    else
        warn "Port $port is not reachable"
        ALL_PORTS_OK=false
    fi
done

if [ "$ALL_PORTS_OK" = false ]; then
    echo ""
    warn "Some ports are not reachable. Possible reasons:"
    echo "  - The Manager (VM) hasn't fully started yet (deploy.sh hasn't finished)"
    echo "  - The VM's firewall/security group rule is blocking ports 1514/1515"
    echo "  - If you're using Tailscale, both sides aren't connected"
    echo ""
    read -rp "Continue anyway? (y/n): " yn
    if [[ "$yn" != "y" && "$yn" != "Y" ]]; then
        echo "Stopped."
        exit 0
    fi
fi

# --- Stop existing agent ---
if systemctl is-active --quiet wazuh-agent 2>/dev/null; then
    step "Existing Wazuh Agent found, stopping it..."
    systemctl stop wazuh-agent
    success "Old agent stopped"
fi

# --- Add Wazuh repo + install ---
step "Installing Wazuh Agent ($PKG_MANAGER)..."

if [ "$PKG_MANAGER" = "apt" ]; then
    # Wazuh GPG key + repo
    if ! apt-get install -y gnupg curl 2>/dev/null; then
        apt-get update -qq && apt-get install -y gnupg curl
    fi

    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list

    apt-get update -qq
    WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_NAME="$AGENT_NAME" \
        apt-get install -y "wazuh-agent=$WAZUH_VERSION-1"

elif [ "$PKG_MANAGER" = "dnf" ] || [ "$PKG_MANAGER" = "yum" ]; then
    # Wazuh repo file
    cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF

    WAZUH_MANAGER="$MANAGER_IP" WAZUH_AGENT_NAME="$AGENT_NAME" \
        $PKG_MANAGER install -y "wazuh-agent-$WAZUH_VERSION-1"
fi

success "Wazuh Agent installed"

# --- Set the Manager IP in ossec.conf (in case it wasn't picked up from the environment variable) ---
OSSEC_CONF="/var/ossec/etc/ossec.conf"
if [ -f "$OSSEC_CONF" ]; then
    # Verify the Manager address was written correctly, fix it manually if needed
    if ! grep -q "<address>$MANAGER_IP</address>" "$OSSEC_CONF"; then
        step "Writing the Manager IP into ossec.conf..."
        sed -i "s|<address>.*</address>|<address>$MANAGER_IP</address>|g" "$OSSEC_CONF"
        success "ossec.conf updated"
    fi
fi

# --- Start the service ---
step "Starting the Wazuh Agent service..."
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent
sleep 5

STATUS=$(systemctl is-active wazuh-agent)
if [ "$STATUS" = "active" ]; then
    success "Service is running (Status: $STATUS)"
else
    warn "Service status: $STATUS — check the logs:"
    echo "  journalctl -u wazuh-agent -n 20"
fi

# --- Show recent logs (to check connection status) ---
step "Recent log entries (waiting 10 seconds)..."
sleep 10
LOG="/var/ossec/logs/ossec.log"
if [ -f "$LOG" ]; then
    grep "wazuh-agentd" "$LOG" | tail -8
else
    warn "Log file not found: $LOG"
fi

echo ""
echo "============================================================"
echo -e "  ${GREEN}DONE${NC}"
echo "============================================================"
echo ""
echo "Confirm the connection on the Manager side (on the VM):"
echo "  docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l"
echo ""
echo "Or in the Dashboard: Agents section → search for '$AGENT_NAME'"
echo ""
