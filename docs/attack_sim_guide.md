# Attack Simulation Guide

A practical, step-by-step walkthrough for running the three attack
simulations (SSH brute force, port scan, LOLBin masquerading) and
confirming Wazuh detects each one. For the technical reference (exact
rule IDs, XML, assumptions), see [`docs/runbook.md`](runbook.md) —
this guide focuses on the "what do I actually type, and on which
machine" side of things.

## 1. The Moving Parts (3 Roles, Not Necessarily 3 Machines)

Every simulation involves up to three roles. Understanding which
machine plays which role is the single most common source of
confusion, so read this before running anything.

| Role | What it is | Example |
|---|---|---|
| **Manager** | The machine running `./bin/fast up` — hosts Wazuh Manager, Indexer, Dashboard | Your cloud VM |
| **Target** | The machine being "attacked" — must have a Wazuh **Agent** installed and connected to the Manager | A Linux/Windows host with `install-wazuh-agent.sh`/`.ps1` already run |
| **Runner** | The machine where you type the `simulate_*.sh` command | Your laptop, or the Target itself |

The Manager and Target can be the same machine (useful for a quick
local test) or different machines (closer to a real deployment). The
Runner **can be a third machine** for two of the three simulations,
but **must be the Target itself** for the LOLBin one — this is called
out explicitly below because it trips people up.

```
 ┌──────────┐        SSH login attempts         ┌──────────┐
 │  Runner  │ ────────────────────────────────> │  Target  │
 │ (laptop) │        port-scan probes           │ (agent)  │
 └──────────┘ ────────────────────────────────> └────┬─────┘
                                                       │ events
                                                       ▼
                                                 ┌──────────┐
                                                 │ Manager  │
                                                 │ (Wazuh)  │
                                                 └──────────┘

 LOLBin simulation is different - Runner IS the Target:

 ┌──────────────────────┐
 │   Target == Runner    │  (wget is copied/executed locally;
 │  (has agent + auditd) │   auditd only sees local processes)
 └───────────┬───────────┘
             │ events
             ▼
       ┌──────────┐
       │ Manager  │
       └──────────┘
```

## 2. What Each Simulation Actually Does

### SSH Brute Force → attempts to look like a password-guessing attack
`simulate_brute_force.sh` uses `sshpass` to attempt 5 SSH logins
against the Target with deliberately wrong passwords, back to back.
This mimics an attacker guessing credentials. Wazuh's default sshd
rule already flags each individual failure; our custom rule
(`100200`) correlates **5 failures from the same source IP within 60
seconds** into a single, higher-severity brute-force alert.

### Port Scan → attempts to look like reconnaissance (nmap)
`simulate_port_scan.sh` sends connection attempts to 9 unusual,
almost-certainly-closed ports on the Target, using `nmap -sS` if
available (a real SYN scan) or a plain Bash `/dev/tcp` loop as a
fallback. Each blocked/refused connection is a low-level signal (rule
`100210`); **8 or more from the same source within 60 seconds**
escalate to a confirmed port-scan alert (rule `100211`).

### LOLBin → attempts to look like a "living-off-the-land" evasion technique
`simulate_lolbin.sh` copies the real `wget` binary to `/tmp/httpd`
(so its process name becomes `httpd`, mimicking a legitimate web
server to evade name-based detection) and executes it with wget-style
arguments. `auditd` on the Target captures the process execution;
Wazuh flags a process calling itself `httpd` but running from a
non-standard path (rule `100220`), and escalates to a confirmed alert
(rule `100221`) when the command line also looks like wget's, not
Apache's.

## 3. One-Time Setup (Do This Before Any Simulation)

1. **Deploy FAST** — on the Manager machine:
   ```bash
   ./bin/fast up
   ```
2. **Connect an Agent** — on the Target machine (Windows: `windows/install-wazuh-agent.ps1`, Linux: `linux/install-wazuh-agent.sh`). Confirm it shows **Active**:
   ```bash
   docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
   ```
3. **Enable prerequisites for port scan & LOLBin** — on the **Target**, as root (SSH brute force needs no extra setup):
   ```bash
   sudo ./tests/acceptance/sim/setup_prereqs.sh
   ```
   This turns on UFW connection logging and installs/configures
   `auditd` to watch process execution. It's safe to re-run.

## 4. Running Each Simulation

### 4.1 SSH Brute Force

**Run from:** the Runner (any machine that can reach the Target over
SSH — your laptop is fine, it does not need Wazuh installed).

```bash
./tests/acceptance/sim/simulate_brute_force.sh <target_host> [ssh_user] [attempts]
```

```bash
# Example
./tests/acceptance/sim/simulate_brute_force.sh 100.87.195.65
```

- `<target_host>` — required; the Target's IP (Tailscale IP recommended)
- `[ssh_user]` — optional, defaults to a non-existent test username (so no real account is touched)
- `[attempts]` — optional, defaults to `5`

Requires `sshpass` on the Runner: `sudo apt-get install -y sshpass`.

### 4.2 Port Scan

**Run from:** the Runner (same flexibility as above).

```bash
./tests/acceptance/sim/simulate_port_scan.sh <target_host>
```

```bash
# Example
./tests/acceptance/sim/simulate_port_scan.sh 100.87.195.65
```

Faster/more realistic with `nmap` installed on the Runner
(`sudo apt-get install -y nmap`), but works without it.

### 4.3 LOLBin (wget masquerading as httpd)

**Run from:** the **Target itself** — log into it first.

```bash
ssh user@<target_host>
cd FAST
./tests/acceptance/sim/simulate_lolbin.sh
```

No arguments needed. The script cleans up after itself (removes the
copied binary).

> ⚠️ Running this from a different machine than the Target does
> nothing useful — `auditd` only observes processes running on its
> own host.

## 5. Confirming Detection (3 Ways)

### A. Wazuh Dashboard (visual)
Log into the Dashboard (`https://<Manager_IP>`) → **Security Events**
→ filter by rule ID (`100200`, `100211`, or `100221`). The alert
should appear within roughly a minute of running the simulation.

### B. Command line (quick check, on the Manager)
```bash
docker exec single-node-wazuh.manager-1 tail -n 50 /var/ossec/logs/alerts/alerts.json | grep '"id":"100200"'
```
(swap the rule ID for the one you're checking)

### C. Automated acceptance tests (recommended — does the waiting/checking for you)

**Run from:** the Runner, with network access to both the Target and
to the Manager's Docker socket (typically this means running pytest
on the Manager machine itself, or a machine with a remote Docker
context configured).

```bash
export TARGET_HOST=<target-ip>
pytest tests/acceptance/ -v
```

Each test: records the current point in `alerts.json` → runs the
matching simulation script → polls for up to 60 seconds for the new
alert → asserts it appeared at the expected severity level. Tests
**skip** (not fail) if `TARGET_HOST` isn't set or the Manager isn't
running, so this never breaks the regular `pytest tests/` unit suite.

## 6. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Brute-force alert never appears | Target's sshd isn't reachable, or the Agent isn't Active | Confirm `agent_control -l` shows Active; confirm port 22 is reachable from the Runner |
| `sshpass: command not found` | Not installed on the Runner | `sudo apt-get install -y sshpass` |
| Port-scan alert never appears | UFW logging not enabled on the Target | Re-run `sudo ./tests/acceptance/sim/setup_prereqs.sh` on the **Target** |
| LOLBin alert never appears | `auditd` not installed/watching, or ran from the wrong machine | Confirm you're on the Target; re-run `setup_prereqs.sh`; check `sudo auditctl -l` shows the `execve` rule |
| LOLBin: `audit.log` not collected | Agent's `ossec.conf` missing the audit `<localfile>` block | `setup_prereqs.sh` prints the exact block to add — add it and `sudo systemctl restart wazuh-agent` |
| Acceptance tests all **skip** | `TARGET_HOST` not set, or Manager container not running | `export TARGET_HOST=...` and/or `./bin/fast status` to confirm the Manager is up |
