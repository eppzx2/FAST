"""
IOC Normalizer Module

Converts data coming from various feeds into a unified schema.

Output Schema (Standard Format):
{
    'ioc_value': str,           # IP, domain, hash, url
    'ioc_type': str,            # 'ip', 'domain', 'hash', 'url'
    'source_feed': str,         # 'feodo', 'urlhaus', etc.
    'first_seen': datetime,     # First-seen date
    'last_seen': datetime,      # Last-seen date
    'tags': list,               # Related tags
}
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def _parse_date(value: Optional[str]) -> str:
    """
    Converts various date formats into an ISO 8601 string.

    If it can't be parsed, returns the current time (UTC) so that
    the system never stores an IOC without a date.

    Args:
        value (str): Raw date string (may be in various formats)

    Returns:
        str: Date in ISO 8601 format (e.g. "2024-01-15T10:30:00")
    """
    if not value:
        return datetime.now(timezone.utc).isoformat()
    
    value = value.strip()
    
    # Formats to try (depending on the feed)
    formats = [
        "%Y-%m-%d %H:%M:%S",   # "2024-01-15 10:30:00" (URLhaus, MalwareBazaar)
        "%Y-%m-%d",             # "2024-01-15" (Feodo last_dns_query)
        "%Y-%m-%dT%H:%M:%S",   # ISO format
    ]
    
    for fmt in formats:
        try:
            return datetime.strptime(value, fmt).isoformat()
        except ValueError:
            continue
    
    logger.warning(f"Could not parse date: '{value}', using the current time")
    return datetime.now(timezone.utc).isoformat()


def _classify_ip_or_cidr(value: str) -> str:
    """
    Determines whether a value is a plain IP or a CIDR block.
    Both are stored as type 'ip' (a CIDR is also an IP-based IOC).

    Args:
        value (str): IP or CIDR string

    Returns:
        str: "ip"
    """
    return "ip"


def normalize_feodo(raw_iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Converts JSON data from Feodo Tracker into the standard format.

    Maps Feodo IPs to type 'ip', keeps the botnet name as a tag.

    Args:
        raw_iocs (List[Dict]): Raw Feodo data (ip_address, botnet,
                                last_dns_query fields expected)

    Returns:
        List[Dict]: List of normalized IOCs
    """
    normalized = []
    
    for raw in raw_iocs:
        try:
            ip_address = raw.get("ip_address")
            if not ip_address:
                logger.warning("Feodo: skipped a record with no 'ip_address' field")
                continue
            
            tags = []
            if raw.get("botnet"):
                tags.append(str(raw["botnet"]))
            if raw.get("malware"):
                tags.append(str(raw["malware"]))
            
            last_seen = _parse_date(raw.get("last_dns_query") or raw.get("last_online"))
            
            normalized.append({
                "ioc_value": ip_address,
                "ioc_type": "ip",
                "source_feed": "feodo",
                "first_seen": last_seen,
                "last_seen": last_seen,
                "tags": tags,
            })
        except Exception as e:
            logger.error(f"Feodo normalization error (record skipped): {str(e)}")
            continue
    
    logger.info(f"Feodo: {len(normalized)}/{len(raw_iocs)} IOCs normalized")
    return normalized


def normalize_urlhaus(raw_iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Converts CSV data from URLhaus into the standard format.

    Maps URLs to type 'url', keeps the threat type as a tag.

    Args:
        raw_iocs (List[Dict]): Raw URLhaus data (url, dateadded,
                                threat, tags fields expected)

    Returns:
        List[Dict]: List of normalized IOCs
    """
    normalized = []
    
    for raw in raw_iocs:
        try:
            url_value = raw.get("url")
            if not url_value:
                logger.warning("URLhaus: skipped a record with no 'url' field")
                continue
            
            tags = []
            if raw.get("threat"):
                tags.append(str(raw["threat"]))
            if raw.get("tags"):
                # URLhaus tags may be in "exe,trojan" format
                tags.extend([t.strip() for t in str(raw["tags"]).split(",") if t.strip()])
            
            date_added = _parse_date(raw.get("dateadded"))
            
            normalized.append({
                "ioc_value": url_value,
                "ioc_type": "url",
                "source_feed": "urlhaus",
                "first_seen": date_added,
                "last_seen": date_added,
                "tags": tags,
            })
        except Exception as e:
            logger.error(f"URLhaus normalization error (record skipped): {str(e)}")
            continue
    
    logger.info(f"URLhaus: {len(normalized)}/{len(raw_iocs)} IOCs normalized")
    return normalized


def normalize_malwarebazaar(raw_iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Converts CSV data from MalwareBazaar into the standard format.

    Maps hashes to type 'hash'. SHA256 is preferred; if not present,
    MD5 is used. The file name and signature are kept as tags.

    Args:
        raw_iocs (List[Dict]): Raw MalwareBazaar data (sha256_hash,
                                md5_hash, first_seen_utc, file_name,
                                signature fields expected)

    Returns:
        List[Dict]: List of normalized IOCs
    """
    normalized = []
    
    for raw in raw_iocs:
        try:
            hash_value = raw.get("sha256_hash") or raw.get("md5_hash")
            if not hash_value:
                logger.warning("MalwareBazaar: skipped a record with no hash field")
                continue
            
            tags = []
            if raw.get("signature"):
                tags.append(str(raw["signature"]))
            if raw.get("file_name"):
                tags.append(str(raw["file_name"]))
            if raw.get("file_type_guess"):
                tags.append(str(raw["file_type_guess"]))
            
            first_seen = _parse_date(raw.get("first_seen_utc"))
            
            normalized.append({
                "ioc_value": hash_value,
                "ioc_type": "hash",
                "source_feed": "malwarebazaar",
                "first_seen": first_seen,
                "last_seen": first_seen,
                "tags": tags,
            })
        except Exception as e:
            logger.error(f"MalwareBazaar normalization error (record skipped): {str(e)}")
            continue
    
    logger.info(f"MalwareBazaar: {len(normalized)}/{len(raw_iocs)} IOCs normalized")
    return normalized


def normalize_spamhaus(raw_iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Converts text data from Spamhaus into the standard format.

    Maps CIDRs/IPs to type 'ip'. Since Spamhaus doesn't provide a
    date, the current time is used as first_seen/last_seen.

    Args:
        raw_iocs (List[Dict]): Raw Spamhaus data (cidr, reason
                                fields expected)

    Returns:
        List[Dict]: List of normalized IOCs
    """
    normalized = []
    now = datetime.now(timezone.utc).isoformat()
    
    for raw in raw_iocs:
        try:
            cidr_value = raw.get("cidr")
            if not cidr_value:
                logger.warning("Spamhaus: skipped a record with no 'cidr' field")
                continue
            
            tags = []
            if raw.get("reason"):
                tags.append(str(raw["reason"]))
            
            normalized.append({
                "ioc_value": cidr_value,
                "ioc_type": "ip",
                "source_feed": "spamhaus",
                "first_seen": now,
                "last_seen": now,
                "tags": tags,
            })
        except Exception as e:
            logger.error(f"Spamhaus normalization error (record skipped): {str(e)}")
            continue
    
    logger.info(f"Spamhaus: {len(normalized)}/{len(raw_iocs)} IOCs normalized")
    return normalized


def normalize_all(raw_feeds: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """
    Normalizes data coming from all feeds.

    Each feed is routed to its own normalizer function. On an
    unknown feed name or a normalization error, that feed is
    skipped and processing continues with the others (no crash).

    Args:
        raw_feeds (Dict): {feed_name: raw_iocs, ...}
                           Example: {"feodo": [...], "urlhaus": [...]}

    Returns:
        List[Dict]: All normalized IOCs (combined into a single list)
    """
    normalize_functions = {
        "feodo": normalize_feodo,
        "urlhaus": normalize_urlhaus,
        "malwarebazaar": normalize_malwarebazaar,
        "spamhaus": normalize_spamhaus,
    }
    
    all_normalized = []
    
    for feed_name, raw_iocs in raw_feeds.items():
        normalize_func = normalize_functions.get(feed_name)
        
        if normalize_func is None:
            logger.warning(f"Unknown feed name: '{feed_name}', skipped")
            continue
        
        try:
            normalized = normalize_func(raw_iocs)
            all_normalized.extend(normalized)
        except Exception as e:
            logger.error(f"Error normalizing '{feed_name}': {str(e)}")
            continue
    
    logger.info(f"Normalized {len(all_normalized)} IOCs in total (from {len(raw_feeds)} feeds)")
    return all_normalized
