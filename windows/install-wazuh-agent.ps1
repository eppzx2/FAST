# ============================================================
# F.A.S.T. - Windows Wazuh Agent Automated Installation
# ============================================================
#
# This script downloads and installs the Wazuh Agent on a Windows
# host machine, configures it to connect to the Manager (cloud VM),
# and starts the service.
#
# REQUIREMENT: Open PowerShell as Administrator, then run:
#
#   .\install-wazuh-agent.ps1 -ManagerIP "<IP>"
#
# ManagerIP - the IP of the cloud VM running the Wazuh Manager.
# This can be the VM's public IP (found on the VM with
# curl ifconfig.me) or, if you're using Tailscale, the VM's
# Tailscale IP (found on the VM with tailscale ip -4).
#
# OPTIONAL: to give the agent a custom name:
#   .\install-wazuh-agent.ps1 -ManagerIP "<IP>" -AgentName "agent-laptop"
# ============================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$ManagerIP,

    [Parameter(Mandatory=$false)]
    [string]$AgentName = $env:COMPUTERNAME,

    [Parameter(Mandatory=$false)]
    [string]$WazuhVersion = "4.9.0"
)

$ErrorActionPreference = "Stop"

function Write-Step($msg) {
    Write-Host ""
    Write-Host "==> $msg" -ForegroundColor Cyan
}

function Write-Success($msg) {
    Write-Host "[OK] $msg" -ForegroundColor Green
}

function Write-Failure($msg) {
    Write-Host "[ERROR] $msg" -ForegroundColor Red
}

# --- Administrator check ---
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Failure "This script requires Administrator privileges."
    Write-Host "Right-click PowerShell and select 'Run as Administrator', then run the script again." -ForegroundColor Yellow
    exit 1
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  F.A.S.T. - Windows Wazuh Agent Installation" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Manager IP : $ManagerIP"
Write-Host "Agent Name : $AgentName"
Write-Host "Version    : $WazuhVersion"

# --- Check that the Manager IP is reachable (ports 1514/1515) ---
Write-Step "Checking Manager reachability ($ManagerIP)..."
$portsOk = $true
foreach ($port in 1514, 1515) {
    $test = Test-NetConnection -ComputerName $ManagerIP -Port $port -WarningAction SilentlyContinue
    if ($test.TcpTestSucceeded) {
        Write-Success "Port $port is reachable"
    } else {
        Write-Failure "Port $port is not reachable"
        $portsOk = $false
    }
}

if (-not $portsOk) {
    Write-Host ""
    Write-Host "WARNING: Some ports are not reachable. Possible reasons:" -ForegroundColor Yellow
    Write-Host "  - The Manager (VM) hasn't fully started yet (deploy.sh isn't finished)"
    Write-Host "  - The VM's firewall/security group rule is blocking ports 1514/1515"
    Write-Host "  - If you're using Tailscale, both sides (this machine and the VM) aren't connected"
    Write-Host ""
    $continue = Read-Host "Do you want to continue anyway? (y/n)"
    if ($continue -ne "y" -and $continue -ne "Y") {
        Write-Host "Stopped."
        exit 1
    }
}

# --- Check for an existing installation ---
$existingService = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Step "Existing Wazuh Agent found, stopping it..."
    Stop-Service -Name "WazuhSvc" -Force -ErrorAction SilentlyContinue
}

# --- Download the MSI ---
Write-Step "Downloading Wazuh Agent MSI (v$WazuhVersion)..."
$msiUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$WazuhVersion-1.msi"
$msiPath = "$env:TEMP\wazuh-agent.msi"

try {
    Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath -UseBasicParsing
    Write-Success "MSI downloaded: $msiPath"
} catch {
    Write-Failure "Failed to download the MSI: $_"
    Write-Host "Check the URL manually: $msiUrl" -ForegroundColor Yellow
    exit 1
}

# --- Install ---
Write-Step "Installing Wazuh Agent..."
$installArgs = "/i `"$msiPath`" /q WAZUH_MANAGER=`"$ManagerIP`" WAZUH_REGISTRATION_SERVER=`"$ManagerIP`" WAZUH_AGENT_NAME=`"$AgentName`""

$process = Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -PassThru -NoNewWindow

if ($process.ExitCode -ne 0) {
    Write-Failure "Installation failed (exit code: $($process.ExitCode))"
    exit 1
}
Write-Success "Wazuh Agent installed"

# --- Start the service ---
Write-Step "Starting the Wazuh Agent service..."
try {
    Start-Service -Name "WazuhSvc"
    Start-Sleep -Seconds 5
    $service = Get-Service -Name "WazuhSvc"
    if ($service.Status -eq "Running") {
        Write-Success "Service is running (Status: $($service.Status))"
    } else {
        Write-Failure "Service failed to start (Status: $($service.Status))"
    }
} catch {
    Write-Failure "Failed to start the service: $_"
    exit 1
}

# --- Show the latest log entries (to check connection status) ---
Write-Step "Latest log entries (waiting 10 seconds)..."
Start-Sleep -Seconds 10
$logPath = "C:\Program Files (x86)\ossec-agent\ossec.log"
if (Test-Path $logPath) {
    Get-Content -Path $logPath -Tail 10
} else {
    Write-Host "Log file not found: $logPath" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  DONE" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Confirm the connection on the Manager side (on the VM):"
Write-Host "  docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l"
Write-Host ""
Write-Host "Or in the Dashboard: Agents section -> search for '$AgentName'"
Write-Host ""
Write-Host "If you see 'SSL error, Connection refused':"
Write-Host "  - Check that the Manager (VM) started up healthy"
Write-Host "  - See docs/DEPLOYMENT_GUIDE.md -> 'Troubleshooting' section"
