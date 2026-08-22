# FAST — Detection Runbook

Custom Wazuh detection rules for three simulated attack scenarios:
SSH brute force, an Nmap-style port scan, and a `wget`-masquerading-
as-`httpd` LOLBin. Rules live in
[`docker/rules/local_rules.xml`](../docker/rules/local_rules.xml)
and are applied the same way as the project's existing TALON IOC
Collector detection rules (via `docker cp`, after the Manager reaches a healthy
state — see `docs/DEPLOYMENT_GUIDE.md`).

> **Looking for a step-by-step walkthrough** (which machine to run
> each script from, exact commands, troubleshooting)? See
> [`docs/SIMULATION_GUIDE.md`](SIMULATION_GUIDE.md). This runbook is
> the technical reference (rule IDs, design assumptions).

## Rule IDs & Expected Alerts

| Rule ID | Scenario | Level | Base rule it builds on | Fires when |
|---|---|---|---|---|
| `100200` | SSH brute force | 10 | `5716` (sshd auth failure) | 5 failed SSH logins from the same source IP within 60s |
| `100210` | Port scan (signal) | 3 | `4100` (firewall rules grouped) | A single blocked/refused connection is logged (low-severity, feeds 100211) |
| `100211` | Port scan (confirmed) | 7 | `100210` | 8+ blocked/refused connection attempts from the same source IP within 60s |
| `100220` | LOLBin (signal) | 6 | `80792` (audit command execution) | A process named `httpd` runs from a non-standard path (feeds 100221) |
| `100221` | LOLBin (confirmed) | 12 | `100220` | The same process's command line also contains wget-style arguments (URL / `-O` / `--no-check-certificate`) |

All rule IDs are in the `100200`–`100229` range, chosen to avoid
collision with the project's existing TALON IOC Collector rules (`100100`–
`100102`) and to stay within Wazuh's recommended custom-rule range
(`100000`–`120000`).

## Design Notes & Assumptions

These were written against Wazuh's publicly documented default
ruleset (verified via Wazuh's own rule-writing documentation and
ruleset source, not assumed from memory):

- **SSH brute force** chains off rule `5716` ("sshd: authentication
  failed", part of the default `sshd_rules.xml`, level 5). No extra
  agent-side configuration is needed — this project's Wazuh agents
  already collect `journald` by default, which includes SSH auth
  events.
- **Port scan**: Wazuh's shipped ruleset does not include a decoder
  literally named `connection_refused`. The closest, verified,
  existing mechanism is the `kernel` decoder feeding rule `4100`
  ("Firewall rules grouped"), used for iptables/UFW log lines. Rule
  `100210` matches on `BLOCK|REJECT|DROP` in the raw log line (since
  the default decoder doesn't expose the firewall action as its own
  field), and `100211` correlates 8+ such events from one source IP
  within 60 seconds. **Requires UFW (or another logged firewall)
  enabled on the target** — see Prerequisites below.
- **LOLBin**: chains off rule `80792` (Wazuh's default "audit command
  execution" rule) and the confirmed default `auditd` decoder fields
  `audit.command` (process name) and `audit.exe` (actual binary
  path). Detection requires *two* signals to fire the high-confidence
  alert (`100221`): the process presents itself as `httpd` from an
  unexpected path, **and** its command line looks like wget's, not
  Apache's. **Requires `auditd` installed and watching `execve` on
  the target** — see Prerequisites below.

  If your specific Wazuh ruleset version includes rule `92053` as an
  equivalent LOLBin/audit rule, you can additionally chain a rule off
  it — check first with:
  ```bash
  docker exec single-node-wazuh.manager-1 grep -r 'id="92053"' /var/ossec/ruleset/rules/
  ```
  This project's rules do not hard-depend on `92053`, since its
  presence/exact meaning could not be verified across all Wazuh
  versions.

## Prerequisites

SSH brute-force detection works out of the box. The other two need
one-time setup **on the target host** (the machine running the Wazuh
Agent being exercised by the simulations — not the Manager):

```bash
sudo ./tests/acceptance/sim/setup_prereqs.sh
```

This enables UFW with connection logging, and installs + configures
`auditd` to watch `execve` syscalls (key `audit-wazuh-c`). If the
agent's `ossec.conf` doesn't yet collect `/var/log/audit/audit.log`,
the script prints the exact `<localfile>` block to add.

## Running the Simulations

All three scripts are under
[`tests/acceptance/sim/`](../tests/acceptance/sim/).

```bash
# From any machine that can reach the target over SSH:
./tests/acceptance/sim/simulate_brute_force.sh <target_host>
./tests/acceptance/sim/simulate_port_scan.sh <target_host>

# Must run ON the target host itself (auditd only sees local execs):
./tests/acceptance/sim/simulate_lolbin.sh
```

## Running the Acceptance Tests

```bash
export TARGET_HOST=<ip-of-the-agent-host>
export TARGET_SSH_USER=root        # used only by the LOLBin test (SSH key auth)
export BRUTE_FORCE_SSH_USER=nonexistent_bruteforce_test_user

pytest tests/acceptance/ -v
```

Each test:
1. Records the current line count of the Manager's `alerts.json`.
2. Runs the corresponding simulation script.
3. Polls `alerts.json` (via `docker exec` on the Manager container)
   for a **new** alert matching the expected rule ID, for up to 60
   seconds.
4. Asserts the alert appeared and its level meets the ticket's
   minimum (`>= 5` for brute force / port scan, `>= 6` for LOLBin).

Tests **skip** (not fail) if `TARGET_HOST` isn't set, or if the Wazuh
Manager container isn't running — they never break the existing
`pytest tests/` unit-test suite, which remains fully offline and
unaffected (`tests/acceptance/` is a separate directory with its own
`conftest.py`).

## Testing Performed

The following was verified in the development sandbox (no live
Docker/Wazuh environment was available there):

- `docker/rules/local_rules.xml` — validated as well-formed XML after
  the additions (parsed successfully, no unclosed tags), and rule IDs
  confirmed unique (no collisions with existing `100100`–`100102`).
- All four new shell scripts (`setup_prereqs.sh`,
  `simulate_brute_force.sh`, `simulate_port_scan.sh`,
  `simulate_lolbin.sh`) — passed `bash -n` syntax checks.
- All four new Python files (`conftest.py` and the three
  `test_*.py` files) — compiled cleanly with `python3 -m py_compile`.
- `pytest tests/acceptance/ -v` — all three tests correctly **skip**
  (Manager not running in the sandbox), confirming the skip logic
  works and nothing crashes without live infrastructure.
- `pytest tests/ -q` (existing unit suite + new acceptance tests
  together) — **56 passed, 3 skipped**, confirming the new files do
  not break any existing test.

**Not yet verified** (requires a live deployed environment): that
each simulation script actually triggers its rule within 60 seconds
against a real Wazuh Manager + Agent. Run the commands under "Running
the Acceptance Tests" above against a deployed FAST stack
(`./bin/fast up` first) to confirm this end-to-end.
