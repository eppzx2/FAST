"""
IOC Feed Fetcher Module

Module responsible for pulling IOCs from various open threat
intelligence feeds.

Supported feeds:
- Feodo Tracker
- URLhaus  
- MalwareBazaar
- Spamhaus DROP
"""

import logging
import requests
import csv
from typing import List, Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)

# Feed URLs
FEED_URLs = {
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/csv_recent/",
    "malwarebazaar": "https://bazaar.abuse.ch/export/csv/recent/",
    "spamhaus": "https://www.spamhaus.org/drop/drop.txt"
}


def fetch_feodo() -> List[Dict[str, Any]]:
    """
    Fetches botnet C2 IP addresses from Feodo Tracker.

    Returns IPs and related metadata in JSON format.

    Returns:
        List[Dict]: List of IOC data
        On error: empty list []

    Example output:
        [
            {
                "botnet": "dridex",
                "ip_address": "192.168.1.1",
                "port": "443",
                "country_code": "RU",
                "last_dns_query": "2024-01-15"
            },
            ...
        ]
    """
    url = FEED_URLs["feodo"]
    iocs = []
    
    try:
        logger.info(f"Fetching data from Feodo Tracker: {url}")
        
        # HTTP request (User-Agent is required)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        # Parse JSON
        data = response.json()
        
        # `data` can be a list, or shaped like {"data": [...]}
        if isinstance(data, dict) and "data" in data:
            iocs = data["data"]
        elif isinstance(data, list):
            iocs = data
        else:
            logger.warning("Feodo: Unexpected JSON structure")
            return []
        
        logger.info(f"Feodo: {len(iocs)} IOCs fetched")
        return iocs
        
    except requests.exceptions.Timeout:
        logger.error("Feodo Tracker: Timeout (15s)")
        return []
    except requests.exceptions.ConnectionError:
        logger.error("Feodo Tracker: Connection error")
        return []
    except requests.exceptions.HTTPError as e:
        logger.error(f"Feodo Tracker: HTTP {e.response.status_code}")
        return []
    except ValueError:
        logger.error("Feodo Tracker: JSON parse error")
        return []
    except Exception as e:
        logger.error(f"Feodo Tracker: Unknown error: {str(e)}")
        return []


def fetch_urlhaus() -> List[Dict[str, Any]]:
    """
    Fetches malicious URLs from URLhaus.

    Returns URLs, dates, and status information in CSV format.

    Returns:
        List[Dict]: List of IOC data
        On error: empty list []

    Example output:
        [
            {
                "id": "12345",
                "dateadded": "2024-01-15 10:30:00",
                "url": "http://evil.com/malware.exe",
                "url_status": "online",
                "threat": "malware_download",
                "tags": "exe,trojan",
                "reporter": "abuse_ch"
            },
            ...
        ]
    """
    url = FEED_URLs["urlhaus"]
    iocs = []
    
    try:
        logger.info(f"Fetching data from URLhaus: {url}")
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        # The URLhaus CSV header has comment lines starting with "# "
        # Format: # id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter
        lines = response.text.splitlines()
        
        # Find the non-comment (data) lines
        data_lines = [line for line in lines if line and not line.startswith("#")]
        
        if not data_lines:
            logger.warning("URLhaus: No data lines found")
            return []
        
        # Find the CSV header (the last "# " comment line, starting with "id,")
        header_line = None
        for line in lines:
            if line.startswith("# id"):
                header_line = line.lstrip("# ").strip()
                break
        
        if header_line is None:
            # Fallback - default header
            fieldnames = ["id", "dateadded", "url", "url_status", "last_online",
                          "threat", "tags", "urlhaus_link", "reporter"]
        else:
            fieldnames = [h.strip() for h in header_line.split(",")]
        
        reader = csv.DictReader(data_lines, fieldnames=fieldnames)
        for row in reader:
            iocs.append(dict(row))
        
        logger.info(f"URLhaus: {len(iocs)} IOCs fetched")
        return iocs
        
    except requests.exceptions.Timeout:
        logger.error("URLhaus: Timeout (15s)")
        return []
    except requests.exceptions.ConnectionError:
        logger.error("URLhaus: Connection error")
        return []
    except requests.exceptions.HTTPError as e:
        logger.error(f"URLhaus: HTTP {e.response.status_code}")
        return []
    except csv.Error as e:
        logger.error(f"URLhaus: CSV parse error: {str(e)}")
        return []
    except Exception as e:
        logger.error(f"URLhaus: Unknown error: {str(e)}")
        return []


def fetch_malwarebazaar() -> List[Dict[str, Any]]:
    """
    Fetches malware hashes from MalwareBazaar.

    Returns MD5, SHA256 hashes and related data in CSV format.

    Returns:
        List[Dict]: List of IOC data
        On error: empty list []

    Example output:
        [
            {
                "first_seen_utc": "2024-01-15 10:30:00",
                "sha256_hash": "abc123...",
                "md5_hash": "def456...",
                "file_name": "malware.exe",
                "file_type": "exe",
                "signature": "TrojanX",
                "reporter": "abuse_ch"
            },
            ...
        ]
    """
    url = FEED_URLs["malwarebazaar"]
    iocs = []
    
    try:
        logger.info(f"Fetching data from MalwareBazaar: {url}")
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        lines = response.text.splitlines()
        data_lines = [line for line in lines if line and not line.startswith("#")]
        
        if not data_lines:
            logger.warning("MalwareBazaar: No data lines found")
            return []
        
        # Find the MalwareBazaar header from the last "# " comment line
        header_line = None
        for line in lines:
            if line.startswith('# "') or line.startswith("# first_seen"):
                header_line = line.lstrip("# ").strip()
                break
        
        if header_line is None:
            fieldnames = ["first_seen_utc", "sha256_hash", "md5_hash", "sha1_hash",
                          "reporter", "file_name", "file_type_guess", "mime_type",
                          "signature", "clamav", "vtpercent", "imphash", "ssdeep", "tlsh"]
        else:
            fieldnames = [h.strip().strip('"') for h in header_line.split(",")]
        
        reader = csv.DictReader(
            data_lines, fieldnames=fieldnames, skipinitialspace=True
        )
        for row in reader:
            # MalwareBazaar values are quoted, clean them up
            clean_row = {
                k: (v.strip().strip('"') if isinstance(v, str) else v)
                for k, v in row.items()
            }
            iocs.append(clean_row)
        
        logger.info(f"MalwareBazaar: {len(iocs)} IOCs fetched")
        return iocs
        
    except requests.exceptions.Timeout:
        logger.error("MalwareBazaar: Timeout (15s)")
        return []
    except requests.exceptions.ConnectionError:
        logger.error("MalwareBazaar: Connection error")
        return []
    except requests.exceptions.HTTPError as e:
        logger.error(f"MalwareBazaar: HTTP {e.response.status_code}")
        return []
    except csv.Error as e:
        logger.error(f"MalwareBazaar: CSV parse error: {str(e)}")
        return []
    except Exception as e:
        logger.error(f"MalwareBazaar: Unknown error: {str(e)}")
        return []


def fetch_spamhaus() -> List[Dict[str, Any]]:
    """
    Fetches spam/botnet IPs from the Spamhaus DROP list.

    Returns IPs in plain text format.

    Returns:
        List[Dict]: List of IOC data
        On error: empty list []

    Example output:
        [
            {"cidr": "192.168.1.0/24", "reason": "SBL12345"},
            ...
        ]
    """
    url = FEED_URLs["spamhaus"]
    iocs = []
    
    try:
        logger.info(f"Fetching data from Spamhaus DROP: {url}")
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        lines = response.text.splitlines()
        
        for line in lines:
            line = line.strip()
            
            # Skip blank lines and full comment lines
            if not line or line.startswith(";"):
                continue
            
            # Format: "192.168.1.0/24 ; SBL12345" or "192.168.1.0/24 ; \"REASON\""
            if ";" in line:
                parts = line.split(";", 1)
                cidr = parts[0].strip()
                reason = parts[1].strip().strip('"') if len(parts) > 1 else ""
            else:
                cidr = line
                reason = ""
            
            if cidr:
                iocs.append({"cidr": cidr, "reason": reason})
        
        logger.info(f"Spamhaus: {len(iocs)} IOCs fetched")
        return iocs
        
    except requests.exceptions.Timeout:
        logger.error("Spamhaus: Timeout (15s)")
        return []
    except requests.exceptions.ConnectionError:
        logger.error("Spamhaus: Connection error")
        return []
    except requests.exceptions.HTTPError as e:
        logger.error(f"Spamhaus: HTTP {e.response.status_code}")
        return []
    except Exception as e:
        logger.error(f"Spamhaus: Unknown error: {str(e)}")
        return []


def fetch_all_feeds() -> Dict[str, List[Dict[str, Any]]]:
    """
    Fetches data from all feeds sequentially.

    Each feed is already error-tolerant within its own function
    (try/except), so if one feed fails the others still continue.

    Returns:
        Dict: {feed_name: list of IOCs, ...}
        Example: {
            "feodo": [...],
            "urlhaus": [...],
            "malwarebazaar": [...],
            "spamhaus": [...]
        }
    """
    results = {}
    
    fetch_functions = {
        "feodo": fetch_feodo,
        "urlhaus": fetch_urlhaus,
        "malwarebazaar": fetch_malwarebazaar,
        "spamhaus": fetch_spamhaus,
    }
    
    for feed_name, fetch_func in fetch_functions.items():
        try:
            logger.info(f"Processing feed '{feed_name}'...")
            results[feed_name] = fetch_func()
        except Exception as e:
            # Each fetcher already handles its own exceptions internally, but
            # this is an extra safety layer against unexpected errors
            logger.error(f"Feed '{feed_name}' failed with an unexpected error: {str(e)}")
            results[feed_name] = []
    
    total = sum(len(v) for v in results.values())
    logger.info(f"All feeds complete. Total: {total} IOCs")
    
    return results
