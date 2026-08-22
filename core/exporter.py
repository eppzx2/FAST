"""
Exporter Module
Exports IOC data in CSV and JSON format.
Output Files (written to the sample_output/ folder by default):
- ioc_export.csv
- ioc_export.json
"""
import logging
import json
import csv
import os
from typing import List, Dict, Any
logger = logging.getLogger(__name__)
EXPORT_DIR = "sample_output"
# CSV column order (matches the database schema)
CSV_FIELDNAMES = [
    "ioc_value", "ioc_type", "source_feed",
    "first_seen", "last_seen", "confidence_score", "tags",
]
def _ensure_export_dir() -> None:
    """
    Ensures the EXPORT_DIR folder exists, creates it if not.
    
    Returns:
        None
    """
    os.makedirs(EXPORT_DIR, exist_ok=True)
def export_to_csv(iocs: List[Dict[str, Any]], filename: str = "ioc_export.csv") -> bool:
    """
    Exports IOC data to a CSV file.
    
    The 'tags' field (a list) is converted to a JSON string so it can
    be stored as a single row value in CSV. Even if an empty list is
    given, a file with just the header row is created.
    
    Args:
        iocs (List[Dict]): List of IOCs
        filename (str): Output file name
        
    Returns:
        bool: Whether it succeeded
    """
    try:
        _ensure_export_dir()
        filepath = os.path.join(EXPORT_DIR, filename)
        
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_FIELDNAMES, extrasaction="ignore")
            writer.writeheader()
            
            for ioc in iocs:
                row = dict(ioc)
                # Convert tags to a JSON string if it's a list, so it fits in a single CSV cell
                if isinstance(row.get("tags"), (list, dict)):
                    row["tags"] = json.dumps(row["tags"], ensure_ascii=False)
                writer.writerow(row)
        
        logger.info(f"CSV export complete: {filepath} ({len(iocs)} IOCs)")
        return True
        
    except (OSError, csv.Error) as e:
        logger.error(f"CSV export error: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected CSV export error: {str(e)}")
        return False
def export_to_json(iocs: List[Dict[str, Any]], filename: str = "ioc_export.json") -> bool:
    """
    Exports IOC data to a JSON file.
    
    Written in a human-readable format (indent=2), with UTF-8 support
    (ensure_ascii=False) so that Azerbaijani characters display correctly.
    
    Args:
        iocs (List[Dict]): List of IOCs
        filename (str): Output file name
        
    Returns:
        bool: Whether it succeeded
    """
    try:
        _ensure_export_dir()
        filepath = os.path.join(EXPORT_DIR, filename)
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(iocs, f, indent=2, ensure_ascii=False, default=str)
        
        logger.info(f"JSON export complete: {filepath} ({len(iocs)} IOCs)")
        return True
        
    except (OSError, TypeError) as e:
        logger.error(f"JSON export error: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected JSON export error: {str(e)}")
        return False
def export_both(iocs: List[Dict[str, Any]]) -> bool:
    """
    Exports IOC data in both CSV and JSON format.
    
    Both exports are attempted independently; even if one fails,
    the other is still attempted (an error in one doesn't block
    the other).
    
    Args:
        iocs (List[Dict]): List of IOCs
        
    Returns:
        bool: True if both exports succeeded, False otherwise
    """
    csv_ok = export_to_csv(iocs)
    json_ok = export_to_json(iocs)
    
    if not csv_ok:
        logger.error("export_both: CSV export failed")
    if not json_ok:
        logger.error("export_both: JSON export failed")
    
    return csv_ok and json_ok
