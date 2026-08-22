"""
Database Module (SQLite)

Stores IOC data in a SQLite database, handles
deduplication and CRUD operations.

Database Schema:
- ioc_value (TEXT): IP, domain, hash, url
- ioc_type (TEXT): 'ip', 'domain', 'hash', 'url'
- source_feed (TEXT): feed name
- first_seen (DATETIME): first seen
- last_seen (DATETIME): last seen
- confidence_score (INTEGER): score 1-100
- tags (TEXT): JSON array
"""

import sqlite3
import logging
import json
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
import os

from core import scoring

logger = logging.getLogger(__name__)

DB_PATH = "ioc_database.db"


def _get_connection() -> sqlite3.Connection:
    """
    Creates and returns a SQLite connection.

    The row factory is set to sqlite3.Row so rows can be
    accessed like a dict (by column name).

    Returns:
        sqlite3.Connection: Open database connection
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_database() -> None:
    """
    Creates the SQLite database in its initial state.

    Creates the table on first run.
    Does nothing on subsequent runs (the table already exists,
    since 'CREATE TABLE IF NOT EXISTS' is used).

    Schema:
        ioc_value (TEXT), ioc_type (TEXT), source_feed (TEXT),
        first_seen (DATETIME), last_seen (DATETIME),
        confidence_score (INTEGER), tags (TEXT)
        UNIQUE(ioc_value, ioc_type) - for dedup

    Returns:
        None
    """
    try:
        conn = _get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ioc (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_value TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                source_feed TEXT NOT NULL,
                first_seen DATETIME NOT NULL,
                last_seen DATETIME NOT NULL,
                confidence_score INTEGER DEFAULT 0,
                tags TEXT DEFAULT '[]',
                UNIQUE(ioc_value, ioc_type)
            )
        """)
        
        # Index for fast lookups
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_ioc_value_type 
            ON ioc(ioc_value, ioc_type)
        """)
        
        conn.commit()
        conn.close()
        logger.info(f"Database ready: {DB_PATH}")
        
    except sqlite3.Error as e:
        logger.error(f"Error creating database: {str(e)}")
        raise


def _upsert_ioc_with_cursor(cursor: sqlite3.Cursor, ioc: Dict[str, Any]) -> bool:
    """
    The core dedup+insert/update logic behind insert_ioc(), but operates
    on an existing cursor (doesn't open a new connection or commit). This
    exists to avoid duplicating code between insert_ioc() and
    insert_batch(), and to let insert_batch() use a single connection for
    thousands of IOCs (opening a separate connection per row severely
    hurts performance).

    Args:
        cursor (sqlite3.Cursor): Active database cursor
        ioc (Dict): Normalized IOC data

    Returns:
        bool: Whether it succeeded (False if validation failed)
    """
    required_keys = {"ioc_value", "ioc_type", "source_feed", "first_seen", "last_seen"}
    if not required_keys.issubset(ioc.keys()):
        missing = required_keys - ioc.keys()
        logger.error(f"IOC is missing required fields: {missing}")
        return False

    existing = cursor.execute(
        "SELECT id, source_feed FROM ioc WHERE ioc_value = ? AND ioc_type = ?",
        (ioc["ioc_value"], ioc["ioc_type"])
    ).fetchone()

    tags_json = json.dumps(ioc.get("tags", []))

    if existing:
        existing_feeds = set(existing["source_feed"].split(","))
        existing_feeds.add(ioc["source_feed"])
        merged_feeds = ",".join(sorted(existing_feeds))

        new_score = scoring.calculate_score({"source_feed": merged_feeds})

        cursor.execute(
            """UPDATE ioc 
               SET last_seen = ?, source_feed = ?, confidence_score = ? 
               WHERE ioc_value = ? AND ioc_type = ?""",
            (ioc["last_seen"], merged_feeds, new_score, ioc["ioc_value"], ioc["ioc_type"])
        )
        logger.debug(f"IOC updated (dedup): {ioc['ioc_value']} ({ioc['ioc_type']}), score={new_score}")
    else:
        initial_score = scoring.calculate_score({"source_feed": ioc["source_feed"]})

        cursor.execute(
            """INSERT INTO ioc 
               (ioc_value, ioc_type, source_feed, first_seen, last_seen, 
                confidence_score, tags) 
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (ioc["ioc_value"], ioc["ioc_type"], ioc["source_feed"],
             ioc["first_seen"], ioc["last_seen"], initial_score, tags_json)
        )
        logger.debug(f"New IOC added: {ioc['ioc_value']} ({ioc['ioc_type']}), score={initial_score}")

    return True


def insert_ioc(ioc: Dict[str, Any]) -> bool:
    """
    Adds a new IOC. Dedup: if the same (ioc_value, ioc_type) already
    exists, don't insert a new record — just update last_seen and
    source_feed.

    When a new record is inserted, confidence_score is set to 1
    (first feed). When an existing record is updated (seen in a new
    feed), confidence_score must be recalculated separately by the
    core.scoring module (see scoring.py). Here only last_seen/
    source_feed are updated, the score itself doesn't change here —
    score calculation is invoked separately in the dedup_score flow.

    Intended for a single IOC. For multiple IOCs use insert_batch()
    (significantly faster, since it uses a single connection and a
    single transaction).

    Args:
        ioc (Dict): Normalized IOC data. Expected keys:
                    ioc_value, ioc_type, source_feed, first_seen,
                    last_seen, tags (optional)

    Returns:
        bool: Whether it succeeded
    """
    try:
        conn = _get_connection()
        cursor = conn.cursor()
        result = _upsert_ioc_with_cursor(cursor, ioc)
        if result:
            conn.commit()
        conn.close()
        return result

    except sqlite3.Error as e:
        logger.error(f"IOC insert error: {str(e)}")
        return False


def insert_batch(iocs: List[Dict[str, Any]]) -> int:
    """
    Adds multiple IOCs at once.

    Uses a SINGLE connection and a SINGLE transaction for performance
    (opening a separate connection per row, especially for thousands
    of IOCs, severely hurts performance — it requires a separate disk
    sync per row). An error on one IOC doesn't stop the others (caught
    inside the loop, the transaction isn't broken).

    Args:
        iocs (List[Dict]): List of IOCs

    Returns:
        int: Number of IOCs successfully added (or updated)
    """
    if not iocs:
        return 0

    success_count = 0

    try:
        conn = _get_connection()
        cursor = conn.cursor()

        for ioc in iocs:
            try:
                if _upsert_ioc_with_cursor(cursor, ioc):
                    success_count += 1
            except Exception as e:
                logger.error(f"IOC skipped in batch insert: {str(e)}")
                continue

        conn.commit()
        conn.close()

    except sqlite3.Error as e:
        logger.error(f"Batch insert connection error: {str(e)}")
        return success_count
    
    logger.info(f"Batch insert: {success_count}/{len(iocs)} IOCs processed")
    return success_count


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    """
    Converts a SQLite Row object to a dict, parsing the tags field from JSON.

    Args:
        row (sqlite3.Row): Database row

    Returns:
        Dict: IOC data (tags as a list)
    """
    result = dict(row)
    try:
        result["tags"] = json.loads(result.get("tags") or "[]")
    except (json.JSONDecodeError, TypeError):
        result["tags"] = []
    return result


def get_ioc(ioc_value: str, ioc_type: str) -> Optional[Dict[str, Any]]:
    """
    Queries the database for a specific IOC.

    Args:
        ioc_value (str): IOC value (IP, domain, etc)
        ioc_type (str): IOC type

    Returns:
        Dict: IOC data (if found), None (otherwise)
    """
    try:
        conn = _get_connection()
        cursor = conn.cursor()
        
        row = cursor.execute(
            "SELECT * FROM ioc WHERE ioc_value = ? AND ioc_type = ?",
            (ioc_value, ioc_type)
        ).fetchone()
        
        conn.close()
        
        if row is None:
            return None
        
        return _row_to_dict(row)
        
    except sqlite3.Error as e:
        logger.error(f"IOC query error: {str(e)}")
        return None


def get_all_iocs() -> List[Dict[str, Any]]:
    """
    Returns all IOCs in the database.

    Returns:
        List[Dict]: All IOCs (tags parsed as a list)
    """
    try:
        conn = _get_connection()
        cursor = conn.cursor()
        
        rows = cursor.execute("SELECT * FROM ioc ORDER BY last_seen DESC").fetchall()
        conn.close()
        
        return [_row_to_dict(row) for row in rows]
        
    except sqlite3.Error as e:
        logger.error(f"Error querying all IOCs: {str(e)}")
        return []


def update_ioc(ioc_value: str, ioc_type: str, last_seen: str, 
               source_feed: str) -> bool:
    """
    Updates an existing IOC's last-seen date and feed.

    Note: insert_ioc() does this automatically during dedup. This
    function is for when a direct update is needed from outside
    (e.g. CLI, API).

    Args:
        ioc_value (str): IOC value
        ioc_type (str): IOC type
        last_seen (str): New last-seen date (ISO 8601 string)
        source_feed (str): Feed name

    Returns:
        bool: Whether it succeeded (also False if the IOC wasn't found)
    """
    try:
        conn = _get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """UPDATE ioc SET last_seen = ?, source_feed = ? 
               WHERE ioc_value = ? AND ioc_type = ?""",
            (last_seen, source_feed, ioc_value, ioc_type)
        )
        
        updated = cursor.rowcount > 0
        conn.commit()
        conn.close()
        
        if not updated:
            logger.warning(f"IOC to update not found: {ioc_value} ({ioc_type})")
        
        return updated
        
    except sqlite3.Error as e:
        logger.error(f"IOC update error: {str(e)}")
        return False


def delete_ioc(ioc_value: str, ioc_type: str) -> bool:
    """
    Deletes an IOC from the database.

    Args:
        ioc_value (str): IOC value
        ioc_type (str): IOC type

    Returns:
        bool: Whether it succeeded (also False if the IOC wasn't found)
    """
    try:
        conn = _get_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "DELETE FROM ioc WHERE ioc_value = ? AND ioc_type = ?",
            (ioc_value, ioc_type)
        )
        
        deleted = cursor.rowcount > 0
        conn.commit()
        conn.close()
        
        return deleted
        
    except sqlite3.Error as e:
        logger.error(f"IOC delete error: {str(e)}")
        return False


def get_count() -> int:
    """
    Returns the total number of IOCs in the database.

    Returns:
        int: IOC count (0 on error)
    """
    try:
        conn = _get_connection()
        cursor = conn.cursor()
        
        row = cursor.execute("SELECT COUNT(*) as cnt FROM ioc").fetchone()
        conn.close()
        
        return row["cnt"] if row else 0
        
    except sqlite3.Error as e:
        logger.error(f"IOC count query error: {str(e)}")
        return 0


def close_database() -> None:
    """
    Closes the database connection.

    Note: since this module opens and closes its own connection in
    every function (connection-per-call pattern), no long-lived open
    connection is kept. This function is provided for future use if a
    connection pool is added; currently no action is needed.

    Returns:
        None
    """
    logger.debug("close_database() called (connection-per-call pattern, no action needed)")
    return None
