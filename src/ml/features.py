"""The shared, ordered model-input contract. Identifiers never enter X."""

from typing import Mapping, Sequence

import numpy as np

from src.preprocessing.schema import verify_ml_feature_safety


FEATURE_ORDER = (
    "query_length", "longest_label_length", "number_of_labels", "entropy",
    "digit_ratio", "special_char_ratio", "subdomain_length", "query_frequency",
    "unique_subdomains", "time_interval",
)
verify_ml_feature_safety(FEATURE_ORDER)


def feature_matrix(rows: Sequence[Mapping[str, float]]) -> np.ndarray:
    """Select exactly ten named features, preserving their canonical order."""
    matrix = np.asarray([[float(row[name]) for name in FEATURE_ORDER] for row in rows], dtype=np.float64)
    matrix = matrix.reshape((-1, len(FEATURE_ORDER)))
    if not np.isfinite(matrix).all():
        raise ValueError("Model features must be finite numbers")
    return matrix
