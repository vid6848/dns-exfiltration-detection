"""Threshold-based statistical baseline for DNS exfiltration detection."""

from .detector import (
    BASELINE_FEATURE_NAMES,
    BaselineDetector,
    BaselineExample,
    ClassificationMetrics,
    ThresholdConfig,
    evaluate,
    load_baseline_examples,
    select_thresholds,
    stratified_split,
)

__all__ = [
    "BASELINE_FEATURE_NAMES",
    "BaselineDetector",
    "BaselineExample",
    "ClassificationMetrics",
    "ThresholdConfig",
    "evaluate",
    "load_baseline_examples",
    "select_thresholds",
    "stratified_split",
]
