"""
Wazuh CDB List Exporter Module

Converts the IOCs in the database into Wazuh's CDB (Constant Database)
list format. This format is used in the Wazuh Manager's <list> rules
(see: infra/ansible/roles/wazuh-manager/templates/ioc_rules.xml.j2).

CDB List Format:
    <value>:<any_value>

    Example:
        1.2.3.4:1
        5.6.7.8:1

Wazuh only uses the part before the `:` as the key; the part after it
is a formal requirement (usually written as "1").

Note: Wazuh CDB lists are intended for IPs (looked up in the
srcip/dstip fields). Therefore only records with ioc_type == "ip"
are exported; hash/url/domain require a different detection
mechanism (future work: FIM/YARA integration).
"""

import logging
import os
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

DEFAULT_CDB_FILENAME = "ioc-ips"


def _extract_ip_value(ioc_value: str) -> str:
    """
    Extracts an IP/CIDR string suitable for the Wazuh CDB list from
    an IOC value.

    Sources like Spamhaus may provide values in CIDR format (e.g.
    "192.168.1.0/24"). The Wazuh CDB list accepts both a single IP
    and a CIDR, so the value is kept as-is.

    Args:
        ioc_value (str): IOC value (IP or CIDR)

    Returns:
        str: Value to be written to the Wazuh CDB list
    """
    return ioc_value.strip()


def export_to_cdb_list(
    iocs: List[Dict[str, Any]],
    output_dir: str = "sample_output",
    filename: str = DEFAULT_CDB_FILENAME,
    min_confidence: int = 0,
) -> bool:
    """
    Writes the 'ip'-type records from an IOC list into a Wazuh CDB
    list file.

    Only records with ioc_type == "ip" are included. The
    min_confidence parameter can be used to filter out low-confidence
    IOCs (e.g. ones seen in only 1 feed) to reduce false-positive risk.

    Args:
        iocs (List[Dict]): List of IOCs from the database
                            (in get_all_iocs() format)
        output_dir (str): Output directory
        filename (str): Output file name (no extension, Wazuh CDB convention)
        min_confidence (int): Minimum confidence_score threshold (default: 0, all)

    Returns:
        bool: Whether it succeeded
    """
    try:
        ip_iocs = [
            ioc for ioc in iocs
            if ioc.get("ioc_type") == "ip" and ioc.get("confidence_score", 0) >= min_confidence
        ]

        if not ip_iocs:
            logger.warning(
                f"CDB export: no 'ip'-type IOCs found meeting min_confidence={min_confidence}"
            )

        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, filename)

        # Avoid duplicates (don't write the same IP twice)
        seen = set()
        lines = []
        for ioc in ip_iocs:
            value = _extract_ip_value(ioc["ioc_value"])
            if value and value not in seen:
                seen.add(value)
                lines.append(f"{value}:1")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
            if lines:
                f.write("\n")

        logger.info(f"Wazuh CDB list export complete: {filepath} ({len(lines)} unique IPs)")
        return True

    except (OSError, TypeError, KeyError) as e:
        logger.error(f"Wazuh CDB export error: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected Wazuh CDB export error: {str(e)}")
        return False


def get_export_stats(iocs: List[Dict[str, Any]], min_confidence: int = 0) -> Dict[str, int]:
    """
    Returns statistics on which IOCs will/won't be included in the
    CDB export.

    For showing "how much is being exported" in the CLI or logs.

    Args:
        iocs (List[Dict]): List of IOCs
        min_confidence (int): Minimum confidence_score threshold

    Returns:
        Dict: {"total": int, "ip_type": int, "exported": int, "filtered_out": int}
    """
    total = len(iocs)
    ip_type = sum(1 for ioc in iocs if ioc.get("ioc_type") == "ip")
    exported = sum(
        1 for ioc in iocs
        if ioc.get("ioc_type") == "ip" and ioc.get("confidence_score", 0) >= min_confidence
    )

    return {
        "total": total,
        "ip_type": ip_type,
        "exported": exported,
        "filtered_out": ip_type - exported,
    }
