# F.A.S.T. — OSINT Threat Aggregation + Fast-Deploy SIEM

**F.A.S.T.** = Fully Automated SIEM & Threat-Intel Tool

A threat aggregation platform that combines open-source (OSINT) threat
intelligence with a fast-deployable Wazuh SIEM. It collects IOCs from
4 free feeds, normalizes and deduplicates them, and pushes them to
Wazuh as real-time detection rules — all with **a single script, in
minutes**.

## 🎯 Purpose

Built for SOC teams working at short-term events (CTFs, trainings,
pentests, International Events) who need a zero-cost, portable monitoring environment
without commercial SIEM licensing or hours of setup.

## ⚡ Quick Start

**Recommended scenario:** the Wazuh SIEM runs on a cloud Ubuntu VM,
and you connect to it with a Wazuh Agent from your own host machine
(Windows/Mac/Linux).

**On the cloud VM** (over SSH):
```bash
git clone <this-repo-url> FAST
cd FAST
./bin/fast up
```

5-10 minutes later: the Wazuh Dashboard is live at the VM's IP
(`https://<VM_IP>`), and IOCs are flowing in. Details:
[`docs/DEPLOYMENT_GUIDE.md`](docs/DEPLOYMENT_GUIDE.md)

**On your host machine:** install the Wazuh Agent and connect it to
the Manager (the cloud VM) — see:
[`docs/DEPLOYMENT_GUIDE.md`](docs/DEPLOYMENT_GUIDE.md#step-5-connect-a-wazuh-agent-for-log-collection)

> For local testing, the same `./bin/fast up` also works on your own
> machine — in that case, `https://localhost` is used instead.

> To set the IP manually: `./bin/fast up --ip <MANAGER_IP>`.
> If omitted, the underlying deployment script auto-detects the IP
> and prints ready-to-use agent-connection commands at the end.

## 🕹️ Management CLI (`bin/fast`)

`bin/fast` is a single entrypoint for operating FAST once it's
checked out, conceptually similar to `systemctl`. It wraps the
existing deployment mechanism (`deploy.sh`) and Docker Compose stack
— you no longer need to call either directly.

```bash
./bin/fast up        # deploy/start FAST (runs deploy.sh, then verifies health)
./bin/fast down       # stop FAST — Wazuh/IOC data is preserved (no -v)
./bin/fast restart    # down + up, data preserved
./bin/fast status     # show Wazuh + IOC Collector health
./bin/fast --help     # usage
```

Works from any directory — `bin/fast` resolves the project root from
its own location, so `/path/to/FAST/bin/fast status` works the same
as `./bin/fast status` from inside the project folder.

> `bin/fast` never runs `docker compose down -v`. Named Docker volumes
> (Wazuh Indexer data, queue, etc.) are only removed if you delete
> them yourself, e.g. via the manual steps in
> [`docs/DEPLOYMENT_GUIDE.md`](docs/DEPLOYMENT_GUIDE.md#stopping--removing).

Advanced/manual usage (`./deploy.sh`, `./refresh_iocs.sh` directly) is
still fully supported and documented in
[`docs/DEPLOYMENT_GUIDE.md`](docs/DEPLOYMENT_GUIDE.md) — `bin/fast up`
is a thin wrapper around the same `deploy.sh`, not a replacement.

Custom attack-detection rules (SSH brute force, port scan, LOLBin
masquerading) are loaded automatically. **SSH brute-force detection
works immediately; port scan and LOLBin detection additionally
require a one-time setup step on each target host**
(`sudo ./tests/acceptance/sim/setup_prereqs.sh`) — see
[`docs/runbook.md`](docs/runbook.md) for rule IDs, prerequisites, and
how to test them.

## 🧩 How It Works

```
4 open feeds → IOC Collector → normalize+dedup+score → Wazuh CDB list → Wazuh Manager → real-time alert
```

1. **TALON IOC Collector** (Python) — collects IOCs from Feodo Tracker,
   URLhaus, MalwareBazaar, and Spamhaus DROP
2. **Normalization + Dedup + Scoring** — unified schema, no duplicates,
   confidence score based on how many feeds an IOC appears in
3. **Wazuh SIEM** (Docker) — Manager + Indexer + Dashboard; IOCs are
   wired into real-time detection rules via a CDB list

## Supported Feeds

1. **Feodo Tracker** — Botnet C2 IP addresses
2. **URLhaus** — Malicious URLs
3. **MalwareBazaar** — Malware hashes (MD5, SHA256)
4. **Spamhaus DROP** — Spam/botnet IP ranges

## Technologies

- Python 3.11+, SQLite3, requests, pytest (56 automated tests)
- Flask (web dashboard)
- Wazuh OSS (Manager + Indexer + Dashboard)
- Docker, Docker Compose, Bash

## Project Structure

```
FAST/
├── core/                       # TALON IOC Collector - core functionality
│   ├── fetchers.py            # 4 feed fetchers
│   ├── normalizer.py          # Normalization
│   ├── db.py                  # SQLite CRUD + dedup + automatic scoring
│   ├── scoring.py             # Confidence scoring logic
│   ├── exporter.py            # CSV/JSON export
│   └── wazuh_export.py        # Wazuh CDB list export
├── docker/
│   ├── ioc-collector.Dockerfile
│   └── rules/local_rules.xml         # IOC detection rules (applied via docker cp)
├── windows/
│   └── install-wazuh-agent.ps1       # Automated Agent install for Windows hosts
├── linux/
│   └── install-wazuh-agent.sh        # Automated Agent install for Linux hosts
├── tests/                      # pytest tests (56 tests)
├── docs/
│   ├── DEPLOYMENT_GUIDE.md    # Step-by-step deployment
│   ├── feed_map.md            # Feed field mapping
│   └── user_guide.md          # CLI usage guide
├── sample_output/              # Sample export files
├── cli.py                      # Terminal interface
├── app.py                      # Web dashboard (Flask)
├── templates/index.html        # Web dashboard UI
├── deploy.sh                   # ⭐ SINGLE-SCRIPT FULL DEPLOYMENT
├── bin/
│   └── fast                    # ⭐ Unified CLI (up/down/restart/status) - wraps deploy.sh
├── refresh_iocs.sh             # Refresh IOCs (manual/cron)
├── requirements.txt
└── README.md                   # This file
```

## CLI Usage (IOC Collector only, no SIEM)

```bash
pip install -r requirements.txt
python cli.py --init-db
python cli.py --fetch                # Fetch from all feeds
python cli.py --show                 # Show results
python cli.py --export csv           # CSV export
python cli.py --export json          # JSON export
python cli.py --export wazuh         # Wazuh CDB list export
```

## Web Dashboard

A lightweight Flask dashboard for browsing IOCs, triggering fetches,
and exporting data without using the CLI.

```bash
pip install -r requirements.txt
python3 app.py
# -> http://localhost:5000
```

Routes:
- `GET  /` — dashboard UI (stats, IOC table, filters)
- `GET  /api/iocs` — paginated, filterable IOC list (JSON)
- `POST /api/fetch` — fetch, normalize, and store from all feeds
- `GET  /api/export?format=csv|json` — download export file
- `GET  /api/stats` — totals by type / feed / confidence score

## Database Schema

```
ioc (table)
├── id                INTEGER PRIMARY KEY
├── ioc_value         TEXT (IP/Domain/Hash/URL)
├── ioc_type          TEXT (ip, domain, hash, url)
├── source_feed       TEXT (feodo, urlhaus, ...)
├── first_seen        DATETIME
├── last_seen         DATETIME
├── confidence_score  INTEGER (based on feed count: 25/50/75/100)
└── tags              TEXT (JSON array)
```

## Fault Tolerance

- If a feed is unreachable → log it and continue, no crash
- Dedup: if `ioc_value + ioc_type` already exists → update `last_seen`,
  don't insert a duplicate
- Scoring: the more distinct feeds an IOC appears in, the higher its score

## Tests

```bash
pip install pytest
python -m pytest tests/ -v   # 56 tests
```

---

**Project:** F.A.S.T. (Fully Automated SIEM & Threat-Intel Tool) 
