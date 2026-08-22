# User Guide

How to use the TALON IoC Collector.

## Setup

### 1. Clone the project

```bash
git clone <repo-url>
cd FAST
```

### 2. Create a virtual environment (optional but recommended)

```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate    # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Initialize the database

```bash
python cli.py --init-db
```

---

## Terminal (CLI) Usage

### Fetch from all feeds

```bash
python cli.py --fetch
```

**Output:**
```
2026-08-07 10:30:45 - root - INFO - Fetched 150 IOCs from Feodo Tracker
2026-08-07 10:31:02 - root - INFO - Fetched 280 IOCs from URLhaus
2026-08-07 10:31:45 - root - INFO - Fetched 95 IOCs from MalwareBazaar
2026-08-07 10:32:15 - root - INFO - Fetched 420 IOCs from Spamhaus
Total: 945 IOCs fetched
```

### Show IOCs

```bash
python cli.py --show
```

### Show the total IOC count

```bash
python cli.py --count
```

**Output:**
```
Total IOCs in database: 2,350
```

### Export as CSV

```bash
python cli.py --export csv
```

**Output:** `sample_output/ioc_export.csv`

### Export as JSON

```bash
python cli.py --export json
```

**Output:** `sample_output/ioc_export.json`

---

## Web Interface Usage

### Start the server

```bash
python app.py
```

**URL:** `http://localhost:5000`

### Dashboard

- Home page: IOC statistics
- Total IOC count
- Breakdown by IOC type (IP, Domain, Hash, URL)
- Breakdown by feed

### API Endpoints

#### Get all IOCs (JSON)

```
GET /api/iocs
```

**Response:**
```json
[
  {
    "ioc_value": "192.168.1.1",
    "ioc_type": "ip",
    "source_feed": "feodo",
    "first_seen": "2024-01-10",
    "last_seen": "2024-01-15",
    "confidence_score": 75,
    "tags": ["botnet", "dridex"]
  },
  ...
]
```

#### Fetch from feeds

```
POST /api/fetch
```

#### Export

```
GET /api/export?format=csv
GET /api/export?format=json
```

#### Get statistics

```
GET /api/stats
```

---

## Automated Refresh (Optional)

To automatically fetch from feeds once a day, use `refresh_iocs.sh`
together with cron:

```bash
crontab -e
# Add the following line:
0 3 * * * /full/path/to/ioc-collector/refresh_iocs.sh >> /var/log/fast-refresh.log 2>&1
```

See `docs/DEPLOYMENT_GUIDE.md` for the full setup (this variant also
pushes refreshed IOCs into Wazuh's detection rules).

---

## Troubleshooting

### Database won't open

```bash
rm ioc_database.db
python cli.py --init-db
```

### A feed won't fetch

- Check the status of the feed's source site
- Try using a VPN
- Check the logs: `python cli.py --fetch 2>&1 | grep ERROR`

### Slow export

- With a large number of IOCs (>10K), use JSON export (faster)

---

## Responsible Use

This project is intended **for legitimate OSINT purposes only**.

Use threat intelligence responsibly.

---

**Last updated:** 2026-08-07
