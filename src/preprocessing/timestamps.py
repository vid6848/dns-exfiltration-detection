"""
Timestamp Parsing and Chronological Standardization Module
Project: DNS Exfiltration Detection Using Network Traffic Analysis (CE305/CS305)

Owner: Yash (Preprocessing and Parsing)

Handles:
- Parsing diverse timestamp formats into timezone-aware UTC datetime objects.
- Formats timestamps to standard string representation: 'YYYY-MM-DD HH:MM:SS.mmm'.
- Derives numeric epoch timestamps (float seconds) for inter-arrival delta-t math.
- Chronological sorting to guarantee reproducible, leak-free sliding window evaluation.

CRITICAL WARNING:
- Raw timestamps and absolute monotonic epoch floats MUST NOT be fed directly to ML.
- They are exclusively anchors for temporal ordering and delta-t / window grouping.
"""

from datetime import datetime, timezone
from typing import Union, List, Any


STANDARD_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S.%f"


def parse_timestamp(ts_value: Union[str, float, int, datetime]) -> datetime:
    """
    Parses a timestamp value into a timezone-aware UTC datetime object.

    Supported inputs:
    - datetime instances
    - Strings: 'YYYY-MM-DD HH:MM:SS.mmm'
    - Strings: 'YYYY-MM-DD HH:MM:SS'
    - ISO 8601 strings: '2025-06-13T09:31:25.123Z'
    - Float/int Unix epoch timestamps (seconds or milliseconds)

    Returns:
        timezone-aware datetime in UTC.
    """
    if isinstance(ts_value, datetime):
        if ts_value.tzinfo is None:
            return ts_value.replace(tzinfo=timezone.utc)
        return ts_value.astimezone(timezone.utc)

    if isinstance(ts_value, (int, float)):
        # Auto-detect milliseconds (> 1e11 is beyond year 5138 in seconds)
        sec = ts_value / 1000.0 if ts_value > 1e11 else float(ts_value)
        return datetime.fromtimestamp(sec, tz=timezone.utc)

    ts_str = str(ts_value).strip()
    if not ts_str:
        raise ValueError("Timestamp value cannot be empty.")

    # Try numeric string (e.g. "1718271085.123")
    try:
        val = float(ts_str)
        sec = val / 1000.0 if val > 1e11 else val
        return datetime.fromtimestamp(sec, tz=timezone.utc)
    except ValueError:
        pass

    # Clean standard ISO 'T' and 'Z'
    clean_str = ts_str.replace("Z", "").replace("T", " ")

    # Standard formats
    candidate_formats = [
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S",
        "%d-%m-%Y %H:%M:%S.%f",
        "%d-%m-%Y %H:%M:%S",
    ]

    for fmt in candidate_formats:
        try:
            parsed = datetime.strptime(clean_str, fmt)
            return parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    # Fallback to datetime.fromisoformat (Python 3.11+)
    try:
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception as e:
        raise ValueError(f"Unable to parse timestamp '{ts_value}': unsupported format.") from e


def format_timestamp_standard(dt: datetime) -> str:
    """
    Formats a datetime object to standard YYYY-MM-DD HH:MM:SS.mmm format
    matching the existing benign and synthetic CSV specifications.
    """
    utc_dt = dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    # Format with microseconds and trim to 3 decimal places (milliseconds)
    formatted = utc_dt.strftime("%Y-%m-%d %H:%M:%S.%f")
    return formatted[:-3]


def to_epoch_seconds(dt: datetime) -> float:
    """Computes exact UTC epoch timestamp in fractional seconds."""
    utc_dt = dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return utc_dt.timestamp()


def sort_records_chronologically(records: List[Any]) -> List[Any]:
    """
    Sorts a collection of records deterministically by chronological epoch timestamp.
    Uses secondary keys (src_ip, requested_server_name, label) to prevent arbitrary tie breaks.
    """
    return sorted(
        records,
        key=lambda r: (
            getattr(r, "epoch_time", 0.0),
            getattr(r, "src_ip", ""),
            getattr(r, "requested_server_name", ""),
            getattr(r, "label", 0),
        )
    )
