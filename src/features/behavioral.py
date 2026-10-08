"""Windowed behavioral DNS features.

The raw client address and timestamps are used only to form behavioral groups and
calculate relative timing.  They are never returned as features.
"""

from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Iterable, List, Tuple, Union

from src.preprocessing.schema import NormalizedRecord


BEHAVIORAL_FEATURE_NAMES = [
    "query_frequency",
    "unique_subdomains",
    "time_interval",
]

WindowEntry = Tuple[float, str]


@dataclass
class _GroupState:
    """State for one ``(src_ip, apex_domain)`` group."""

    window: Deque[WindowEntry] = field(default_factory=deque)
    subdomain_counts: Counter = field(default_factory=Counter)
    previous_epoch_time: float | None = None


class BehavioralFeatureExtractor:
    """Extract behavioral features from chronological DNS records.

    A record's sliding window is inclusive: it contains all queries from the
    same ``(src_ip, apex_domain)`` whose ``epoch_time`` is in
    ``[current_time - window_seconds, current_time]``.  The current query is
    included in both count features.  ``time_interval`` is measured against
    the previous query in the same group, even when that prior query is no
    longer in the sliding window.  A group's first query has ``-1.0`` as its
    interval.
    """

    def __init__(self, window_seconds: float = 60.0) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be greater than zero")
        self.window_seconds = float(window_seconds)
        self._groups: Dict[Tuple[str, str], _GroupState] = {}

    def extract(self, record: NormalizedRecord) -> Dict[str, Union[int, float]]:
        """Return behavioral features for one chronologically ordered record."""
        group_key = (record.src_ip, record.apex_domain)
        state = self._groups.setdefault(group_key, _GroupState())
        current_time = float(record.epoch_time)

        if state.previous_epoch_time is not None and current_time < state.previous_epoch_time:
            raise ValueError(
                "Records must be chronological within each (src_ip, apex_domain) group"
            )

        window_start = current_time - self.window_seconds
        while state.window and state.window[0][0] < window_start:
            _, expired_subdomain = state.window.popleft()
            state.subdomain_counts[expired_subdomain] -= 1
            if state.subdomain_counts[expired_subdomain] == 0:
                del state.subdomain_counts[expired_subdomain]

        if state.previous_epoch_time is None:
            time_interval = -1.0
        else:
            time_interval = current_time - state.previous_epoch_time

        state.window.append((current_time, record.subdomain))
        state.subdomain_counts[record.subdomain] += 1
        state.previous_epoch_time = current_time

        return {
            "query_frequency": len(state.window),
            "unique_subdomains": len(state.subdomain_counts),
            "time_interval": float(time_interval),
        }


def extract_behavioral_features(
    records: Iterable[NormalizedRecord], window_seconds: float = 60.0
) -> List[Dict[str, Union[int, float]]]:
    """Extract behavioral features for chronological records in input order."""
    extractor = BehavioralFeatureExtractor(window_seconds=window_seconds)
    return [extractor.extract(record) for record in records]
