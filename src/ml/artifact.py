"""Load the saved inference bundle and apply its selected decision threshold."""

from pathlib import Path

import joblib
import numpy as np

from .features import FEATURE_ORDER, feature_matrix


def load_model(path: Path):
    """Load a trusted project artifact; joblib uses executable pickle data."""
    bundle = joblib.load(path)
    if bundle.get("schema_version") != 1 or tuple(bundle.get("feature_order", ())) != FEATURE_ORDER:
        raise ValueError("Unsupported model artifact or feature order")
    if bundle["model"].n_features_in_ != len(FEATURE_ORDER):
        raise ValueError("Saved estimator does not match the ten-feature contract")
    if list(bundle["model"].classes_) != [0, 1]:
        raise ValueError("Saved estimator must use classes [0, 1]")
    if not 0 < bundle["decision_threshold"] < 1:
        raise ValueError("Invalid artifact decision threshold")
    return bundle


def predict_features(bundle, rows):
    """Return (binary predictions, attack probabilities) for named feature rows.

    Use this instead of estimator.predict(): validation may select a threshold
    other than 0.5. Callers must supply the SAME behavioral feature definitions.
    """
    if tuple(bundle["feature_order"]) != FEATURE_ORDER:
        raise ValueError("Feature order mismatch")
    matrix = feature_matrix(rows)
    if not len(matrix):
        return np.asarray([], dtype=np.int64), np.asarray([], dtype=float)
    probabilities = bundle["model"].predict_proba(matrix)[:, 1]
    return (probabilities >= bundle["decision_threshold"]).astype(np.int64), probabilities
