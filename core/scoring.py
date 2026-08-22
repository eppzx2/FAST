"""
Confidence Scoring Module
Assigns a confidence score to IOCs.
Scoring Logic (simple counting logic):
- The IOC's source_feed field holds comma-separated feed names
  (see: core/db.py insert_ioc() dedup merge logic)
- The more distinct feeds it appears in, the higher the score:
  1 feed  -> 25 points
  2 feeds -> 50 points
  3 feeds -> 75 points
  4 feeds -> 100 points
- General formula: min(100, feed_count * 25)
"""
import logging
from typing import Dict, Any, List
logger = logging.getLogger(__name__)
# Points added per distinct feed
SCORE_PER_FEED = 25
MAX_SCORE = 100
def calculate_score(ioc: Dict[str, Any]) -> int:
    """
    Calculates the confidence score for a single IOC.
    
    Calculated based on the number of distinct (comma-separated)
    feeds in the IOC's 'source_feed' field. If the field is empty
    or missing, 0 is returned.
    
    Args:
        ioc (Dict): IOC data ('source_feed' key expected,
                    e.g. "feodo,urlhaus" or just "feodo")
        
    Returns:
        int: Confidence score (in the range 0-100)
    """
    source_feed = ioc.get("source_feed", "")
    
    if not source_feed:
        logger.warning("IOC has no 'source_feed' field, setting score to 0")
        return 0
    
    # Count the distinct comma-separated feed names
    feed_names = {f.strip() for f in source_feed.split(",") if f.strip()}
    feed_count = len(feed_names)
    
    score = min(MAX_SCORE, feed_count * SCORE_PER_FEED)
    return score
def update_scores_batch(iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Updates the score for multiple IOCs.
    
    Replaces each IOC's 'confidence_score' field with the result of
    calculate_score(). Does not modify the original list, returns a
    new list.
    
    Args:
        iocs (List[Dict]): List of IOCs
        
    Returns:
        List[Dict]: List of IOCs with the confidence_score field updated
    """
    updated = []
    
    for ioc in iocs:
        try:
            new_ioc = dict(ioc)
            new_ioc["confidence_score"] = calculate_score(ioc)
            updated.append(new_ioc)
        except Exception as e:
            logger.error(f"Error calculating score (IOC kept unchanged): {str(e)}")
            updated.append(ioc)
    
    return updated
