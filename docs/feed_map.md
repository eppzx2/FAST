# Feed Mapping

Explains how data from each feed is mapped to the standard schema.

## 1. Feodo Tracker

**Feed URL:** `https://feodotracker.abuse.ch/downloads/ipblocklist.json`

**Format:** JSON

**Raw Structure:**
```json
{
  "botnet": "dridex",
  "ip_address": "192.168.1.1",
  "port": "443",
  "country_code": "RU",
  "last_dns_query": "2024-01-15"
}
```

**Mapping:**
| Feodo Field | Standard Field | Note |
|---|---|---|
| `ip_address` | `ioc_value` | IP address |
| - | `ioc_type` | `"ip"` |
| - | `source_feed` | `"feodo"` |
| `last_dns_query` | `last_seen` | Date is parsed |
| - | `first_seen` | Same as `last_seen` |
| `botnet` | `tags` | Botnet name as a tag |

---

## 2. URLhaus

**Feed URL:** `https://urlhaus.abuse.ch/downloads/csv_recent/`

**Format:** CSV

**Raw Structure:**
```csv
id,date_added,url,url_status,threat,reporter
1,2024-01-15,http://evil.com/malware.exe,online,Trojan,abuse.ch
```

**Mapping:**
| URLhaus Field | Standard Field | Note |
|---|---|---|
| `url` | `ioc_value` | URL address |
| - | `ioc_type` | `"url"` |
| - | `source_feed` | `"urlhaus"` |
| `date_added` | `first_seen` | Date is parsed |
| `date_added` | `last_seen` | Date is parsed |
| `threat` | `tags` | Threat type as a tag |

---

## 3. MalwareBazaar

**Feed URL:** `https://bazaar.abuse.ch/export/csv/recent/`

**Format:** CSV

**Raw Structure:**
```csv
sha256,md5,first_submission,last_analysis,file_name
abc123,def456,2024-01-10,2024-01-15,malware.exe
```

**Mapping:**
| MalwareBazaar Field | Standard Field | Note |
|---|---|---|
| `sha256` or `md5` | `ioc_value` | Hash value |
| - | `ioc_type` | `"hash"` |
| - | `source_feed` | `"malwarebazaar"` |
| `first_submission` | `first_seen` | Date is parsed |
| `last_analysis` | `last_seen` | Date is parsed |
| `file_name` | `tags` | File name as a tag |

---

## 4. Spamhaus DROP

**Feed URL:** `https://www.spamhaus.org/drop/drop.txt`

**Format:** Plain text (one IP per line, followed by `; "REASON"`)

**Raw Structure:**
```
; Spamhaus DROP List
192.168.1.0/24 ; "Botnet"
10.0.0.0/8 ; "Spam Source"
```

**Mapping:**
| Spamhaus Field | Standard Field | Note |
|---|---|---|
| IP address | `ioc_value` | CIDR or plain IP |
| - | `ioc_type` | `"ip"` |
| - | `source_feed` | `"spamhaus"` |
| - | `first_seen` | Current timestamp |
| - | `last_seen` | Current timestamp |
| Comment (`REASON`) | `tags` | Reason as a tag |

---

## Standard Output Schema

```json
{
  "ioc_value": "192.168.1.1",
  "ioc_type": "ip",
  "source_feed": "feodo",
  "first_seen": "2024-01-10T10:30:00",
  "last_seen": "2024-01-15T15:45:00",
  "confidence_score": 75,
  "tags": ["botnet", "dridex"]
}
```

---

**Last updated:** 2026-08-07
