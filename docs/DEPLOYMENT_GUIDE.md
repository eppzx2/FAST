# F.A.S.T. — Deployment Guide

This document explains how to bring up the F.A.S.T. (OSINT IOC
Collector + Wazuh SIEM) environment from scratch in minutes.

**Setup order:** Tailscale → deploy the SIEM → open the Dashboard →
run the web app → connect agents.

## Requirements

- Docker (20.10+) and the Docker Compose plugin
- Git
- ~4GB free RAM, ~10GB free disk
- Linux, macOS, or Windows (via WSL2)

Check on the machine that will run the deployment script (the cloud VM):
```bash
docker --version
docker compose version
git --version
```

No Docker? https://docs.docker.com/engine/install/

---

## Step 1: Install Tailscale

Tailscale creates a private, encrypted network between your host
machine and the cloud VM, so agents can reach the Wazuh Manager
without opening any ports to the public internet, and without dealing
with changing public IPs.

Create a free account first at https://tailscale.com/, then install
on both sides:

### On the Cloud VM (Linux)

Run these commands over SSH, on the VM:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```

The second command prints a login link — open it in a browser and
sign in with the same account.

**Finding the VM's Tailscale IP:**

```bash
tailscale ip -4
```

This is the IP you'll use later as the Wazuh Manager's address (for
`deploy.sh --ip`, the Dashboard URL, and agent connections).

### On the Windows Host

Just install the Tailscale app — no commands needed:

1. Go to https://tailscale.com/download/windows and install it
2. Sign in with the same account when prompted

**Finding this machine's Tailscale IP:**

Click the Tailscale icon in the system tray (near the clock) — your
device's IP is shown under "This device."

---

## Step 2: Run the Deployment Script (on the Cloud VM)

Over SSH, on the VM:

```bash
git clone <this-repo-url> FAST.git
cd FAST
./deploy.sh --ip <VM_TAILSCALE_IP>
```

Replace `<VM_TAILSCALE_IP>` with the IP you found in Step 1. Passing
`--ip` explicitly is recommended so the script's printed URLs and
agent-connection commands are correct from the start.

> If you omit `--ip`, the script auto-detects an IP on its own
> (Tailscale → public IP → local IP, in that order) and prints
> ready-to-use agent-connection commands at the end — but setting it
> explicitly avoids any ambiguity.

> For local testing, the same command also works on your own machine
> (WSL/Linux/Mac) — in that case, the Manager IP will be `localhost`
> unless you pass `--ip`.

That's it. The script automatically:

1. Downloads the official Wazuh Docker stack (first run only, ~1 min)
2. Generates SSL certificates (first run only, ~1 min)
3. Wires the TALON IOC Collector's custom detection rule into Wazuh
4. Starts Wazuh Manager+Indexer+Dashboard (`docker compose up -d`)
5. Builds the IOC Collector image
6. Fetches IOCs from 4 open feeds (Feodo, URLhaus, MalwareBazaar,
   Spamhaus), normalizes them, deduplicates, and computes confidence
   scores
7. Converts IP-type IOCs into Wazuh CDB list format
8. Copies the CDB list into the Wazuh Manager container and applies it

**Total time: ~5-10 minutes** (mostly Docker image downloads).

---

## Step 3: Open the Wazuh Dashboard

In a browser, on your host machine:

```
https://<MANAGER_TAILSCALE_IP>
```

Use the VM's Tailscale IP from Step 1 (the same one you passed to
`--ip`).

- User: `admin`
- Password: `SecretPassword` (Wazuh's default password — **change it
  on first login**)
- On the "Not secure" warning: Advanced → Proceed (this is expected,
  the certificate is self-signed)

In the Dashboard, go to **Threat Intelligence → Rules** in the left
menu and confirm the custom rules with IDs `100100`-`100102` exist.

---

## Step 4: Run the Web App (app.py)

A lightweight Flask dashboard for browsing IOCs, triggering fetches,
and exporting data without using the CLI. This can run on the VM
alongside the SIEM, or on any machine with a copy of the project.

```bash
pip install -r requirements.txt
python3 app.py
```

Open in a browser:

```
http://<HOST_RUNNING_APP_PY>:5000
```

(`http://localhost:5000` if running on your own machine, or the VM's
Tailscale IP on port 5000 if running on the VM.)

Routes:
- `GET  /` — dashboard UI (stats, IOC table, filters)
- `GET  /api/iocs` — paginated, filterable IOC list (JSON)
- `POST /api/fetch` — fetch, normalize, and store from all feeds
- `GET  /api/export?format=csv|json` — download export file
- `GET  /api/stats` — totals by type / feed / confidence score

---

## Step 5: Connect a Wazuh Agent (for Log Collection)

### On a Windows Host Machine (Automated Script — Recommended)

The `windows/install-wazuh-agent.ps1` script handles download,
install, configuration, and service startup in one command, and also
checks upfront whether the Manager is reachable.

**Open PowerShell as Administrator:**

```powershell
cd FAST\windows
.\install-wazuh-agent.ps1 -ManagerIP "<MANAGER_TAILSCALE_IP>"
```

You can also give the agent a custom name:

```powershell
.\install-wazuh-agent.ps1 -ManagerIP "<MANAGER_TAILSCALE_IP>" -AgentName "agent-laptop"
```

The script automatically:
- Checks for Administrator privileges
- Tests whether ports 1514/1515 are reachable on the Manager
- Downloads and installs the MSI
- Starts the service and shows the latest log entries



#### Windows Troubleshooting

**Script won't run — "running scripts is disabled on this system":**

By default, Windows blocks running `.ps1` scripts. To allow it for the
current PowerShell window only (reverts once the window is closed):

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
```

**Disconnecting the agent (stop the service immediately):**

```powershell
Stop-Service -Name "WazuhSvc"
```

**Preventing the agent from auto-starting on reboot:**

```powershell
Set-Service -Name "WazuhSvc" -StartupType Disabled
```

**Checking the agent's current status:**

```powershell
Get-Service -Name "WazuhSvc"
```


### On a Linux Target Machine (Automated Script)

The `linux/install-wazuh-agent.sh` script works the same way — it
detects the package manager (apt or yum/dnf), tests port
reachability, installs the agent, and starts the service.

```bash
sudo ./install-wazuh-agent.sh --ip <MANAGER_TAILSCALE_IP>
sudo ./install-wazuh-agent.sh --ip <MANAGER_TAILSCALE_IP> --name "my-server"
```

#### Linux Troubleshooting

**Disconnecting the agent (stop the service immediately):**

```bash
sudo systemctl stop wazuh-agent
```

**Preventing the agent from auto-starting on reboot:**

```bash
sudo systemctl disable wazuh-agent
```

**Checking the agent's current status:**

```bash
sudo systemctl status wazuh-agent
```

**Re-enabling and starting it again:**

```bash
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```


### Why Tailscale IPs Work Well Here

Because both the host machine and the VM are connected via Tailscale,
the host makes an **outbound** connection to the Manager over the
Tailscale network — no inbound firewall rule is needed on the host,
and no ports need to be opened to the public internet on the VM.
Tailscale IPs also stay fixed, so this address won't change even if
the VM's public IP does.

### Confirming the Connection

On the Manager side (on the VM, wherever the Wazuh container runs):

```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
```

The new agent should show as **Active**. It can also be checked from
the Dashboard's **Agents** section.

---

## Step 6: Enable Attack-Detection Rules (Port Scan & LOLBin)

`./bin/fast up` / `./deploy.sh` automatically loads the project's
custom Wazuh rules, including SSH brute force, port scan, and LOLBin
(`wget` masquerading as `httpd`) detection. **SSH brute-force
detection works immediately** — no extra setup needed.

**Port scan and LOLBin detection additionally require one-time setup
on each target host** (the machine running the Wazuh Agent you want
these rules to cover), because they depend on log sources that aren't
collected by default: firewall logs (for port scan) and `auditd`
process-execution logs (for LOLBin).

Run this once, as root, **on the target host**:

```bash
sudo ./tests/acceptance/sim/setup_prereqs.sh
```

This enables UFW with connection logging, and installs/configures
`auditd` to watch `execve` syscalls. Full details, rule IDs, and how
to test each rule: [`docs/runbook.md`](runbook.md).

---

## Refreshing IOCs

To pull fresh IOCs without repeating the full deploy:

```bash
./refresh_iocs.sh
```

For automatic (daily) refresh, add this to the host's crontab:

```bash
crontab -e
# Add the following line:
0 3 * * * /full/path/to/FAST/refresh_iocs.sh >> /var/log/fast-refresh.log 2>&1
```

## Stopping / Removing

```bash
# Stop temporarily (data is kept)
cd wazuh-docker/single-node
docker compose down

# Start again
docker compose up -d

# Remove completely (including data)
docker compose down -v
cd ../..
rm -rf wazuh-docker
```



## Where to Run It: Cloud VM vs Local

The steps above work identically in any Docker-capable environment.
The **recommended scenario** is: run `deploy.sh` on a cloud Ubuntu VM
(Manager, Indexer, Dashboard, and IOC Collector all live there), and
connect to it with an Agent from your own host machine (as shown
above). For local testing, the same script works just as well on your
own computer — no code changes needed, it just depends on where you
run it from.
