"""Configurable threshold baseline built from derived DNS features only.

The tuning API deliberately accepts only training and validation examples.
Callers must evaluate the returned detector on a held-out test split separately.
"""

import csv
import itertools
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence, Tuple

from src.features.behavioral import BehavioralFeatureExtractor
from src.features.per_query import extract_per_query_features
from src.preprocessing.pipeline import PreprocessingPipeline
from src.preprocessing.schema import verify_ml_feature_safety


BASELINE_FEATURE_NAMES: Tuple[str, ...] = (
    "query_length",
    "entropy",
    "query_frequency",
    "unique_subdomains",
)
FEATURE_CSV_REQUIRED_COLUMNS = frozenset((*BASELINE_FEATURE_NAMES, "label"))

# A count of one is the current query itself, not evidence of repeated or
# diverse behavior. These bounds keep count-based indicators interpretable;
# all stronger cutoffs are still selected from the training partition.
MINIMUM_MEANINGFUL_THRESHOLDS = {
    "query_frequency": 2.0,
    "unique_subdomains": 2.0,
}


@dataclass(frozen=True)
class ThresholdConfig:
    """Minimum values for suspicious indicators and required indicator votes."""

    query_length: float
    entropy: float
    query_frequency: float
    unique_subdomains: float
    min_indicators: int = 2

    def __post_init__(self) -> None:
        if not 1 <= self.min_indicators <= len(BASELINE_FEATURE_NAMES):
            raise ValueError(
                f"min_indicators must be between 1 and {len(BASELINE_FEATURE_NAMES)}"
            )

    def as_dict(self) -> Dict[str, float]:
        """Return the four configured feature thresholds."""
        return {feature_name: getattr(self, feature_name) for feature_name in BASELINE_FEATURE_NAMES}


@dataclass(frozen=True)
class BaselineExample:
    """One label and its derived numeric baseline features."""

    features: Mapping[str, float]
    label: int


@dataclass(frozen=True)
class ClassificationMetrics:
    """Confusion matrix counts and derived binary-classification metrics."""

    true_positives: int
    true_negatives: int
    false_positives: int
    false_negatives: int

    @property
    def total(self) -> int:
        return self.true_positives + self.true_negatives + self.false_positives + self.false_negatives

    @property
    def accuracy(self) -> float:
        return (self.true_positives + self.true_negatives) / self.total if self.total else 0.0

    @property
    def precision(self) -> float:
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def f1_score(self) -> float:
        denominator = self.precision + self.recall
        return 2 * self.precision * self.recall / denominator if denominator else 0.0

    @property
    def false_positive_rate(self) -> float:
        denominator = self.false_positives + self.true_negatives
        return self.false_positives / denominator if denominator else 0.0


class BaselineDetector:
    """Flag a query when enough derived features meet their thresholds."""

    def __init__(self, config: ThresholdConfig) -> None:
        verify_ml_feature_safety(BASELINE_FEATURE_NAMES)
        self.config = config

    def suspicious_indicator_count(self, features: Mapping[str, float]) -> int:
        """Count derived feature values that meet their configured threshold."""
        return sum(
            float(features[feature_name]) >= threshold
            for feature_name, threshold in self.config.as_dict().items()
        )

    def predict(self, features: Mapping[str, float]) -> int:
        """Return 1 for suspicious and 0 for benign."""
        return int(self.suspicious_indicator_count(features) >= self.config.min_indicators)


def evaluate(detector: BaselineDetector, examples: Iterable[BaselineExample]) -> ClassificationMetrics:
    """Evaluate a detector without changing its thresholds or feature data."""
    tp = tn = fp = fn = 0
    for example in examples:
        prediction = detector.predict(example.features)
        if example.label == 1 and prediction == 1:
            tp += 1
        elif example.label == 0 and prediction == 0:
            tn += 1
        elif example.label == 0 and prediction == 1:
            fp += 1
        else:
            fn += 1
    return ClassificationMetrics(tp, tn, fp, fn)


def _quantile(values: Sequence[float], quantile: float) -> float:
    if not values:
        raise ValueError("Cannot derive thresholds from an empty training set")
    ordered = sorted(values)
    index = round((len(ordered) - 1) * quantile)
    return ordered[index]


def _candidate_thresholds(
    training_examples: Sequence[BaselineExample], feature_name: str, max_candidates: int
) -> List[float]:
    """Return the strongest single-feature cutoffs derived solely from training data."""
    values_by_label = {
        label: [float(example.features[feature_name]) for example in training_examples if example.label == label]
        for label in (0, 1)
    }
    if not values_by_label[0] or not values_by_label[1]:
        raise ValueError("Training data must contain both benign and exfiltration labels")

    candidate_values = {
        _quantile(values_by_label[label], quantile)
        for label in (0, 1)
        for quantile in (0.0, 0.10, 0.25, 0.50, 0.75, 0.90, 1.0)
    }
    minimum_threshold = MINIMUM_MEANINGFUL_THRESHOLDS.get(feature_name, float("-inf"))
    candidate_values = {value for value in candidate_values if value >= minimum_threshold}
    if not candidate_values:
        candidate_values = {minimum_threshold}
    scored_candidates = []
    for threshold in candidate_values:
        tp = tn = fp = fn = 0
        for example in training_examples:
            prediction = int(float(example.features[feature_name]) >= threshold)
            if example.label == 1 and prediction == 1:
                tp += 1
            elif example.label == 0 and prediction == 0:
                tn += 1
            elif example.label == 0:
                fp += 1
            else:
                fn += 1
        metrics = ClassificationMetrics(tp, tn, fp, fn)
        scored_candidates.append((metrics.f1_score, metrics.false_positive_rate, -metrics.recall, threshold))

    scored_candidates.sort(key=lambda candidate: (-candidate[0], candidate[1], candidate[2], candidate[3]))
    return [candidate[3] for candidate in scored_candidates[:max_candidates]]


def select_thresholds(
    training_examples: Sequence[BaselineExample],
    validation_examples: Sequence[BaselineExample],
    max_candidates_per_feature: int = 3,
) -> Tuple[BaselineDetector, ClassificationMetrics]:
    """Select a baseline rule using training-derived candidates and validation metrics.

    Test examples are intentionally absent from this signature, which prevents
    held-out test labels from being used in threshold selection.
    """
    if max_candidates_per_feature < 1:
        raise ValueError("max_candidates_per_feature must be at least one")
    if not validation_examples:
        raise ValueError("Validation data cannot be empty")

    candidate_values = [
        _candidate_thresholds(training_examples, feature_name, max_candidates_per_feature)
        for feature_name in BASELINE_FEATURE_NAMES
    ]

    best_detector = None
    best_metrics = None
    validation_labels = [example.label for example in validation_examples]
    indicator_vectors = [
        [
            [float(example.features[feature_name]) >= threshold for example in validation_examples]
            for threshold in feature_thresholds
        ]
        for feature_name, feature_thresholds in zip(BASELINE_FEATURE_NAMES, candidate_values)
    ]

    for threshold_indexes in itertools.product(*(range(len(values)) for values in candidate_values)):
        thresholds = tuple(
            candidate_values[feature_index][threshold_index]
            for feature_index, threshold_index in enumerate(threshold_indexes)
        )
        indicator_columns = tuple(
            indicator_vectors[feature_index][threshold_index]
            for feature_index, threshold_index in enumerate(threshold_indexes)
        )
        # The documented statistical baseline requires corroboration from
        # multiple indicators; manual ThresholdConfig use may still choose one.
        for min_indicators in range(2, len(BASELINE_FEATURE_NAMES) + 1):
            config = ThresholdConfig(*thresholds, min_indicators=min_indicators)
            tp = tn = fp = fn = 0
            for label, query_length, entropy, query_frequency, unique_subdomains in zip(
                validation_labels, *indicator_columns
            ):
                prediction = int(
                    query_length + entropy + query_frequency + unique_subdomains >= min_indicators
                )
                if label == 1 and prediction == 1:
                    tp += 1
                elif label == 0 and prediction == 0:
                    tn += 1
                elif label == 0:
                    fp += 1
                else:
                    fn += 1
            detector = BaselineDetector(config)
            metrics = ClassificationMetrics(tp, tn, fp, fn)
            score = (metrics.f1_score, -metrics.false_positive_rate, metrics.recall, metrics.precision)
            if best_metrics is None or score > (
                best_metrics.f1_score,
                -best_metrics.false_positive_rate,
                best_metrics.recall,
                best_metrics.precision,
            ):
                best_detector = detector
                best_metrics = metrics

    return best_detector, best_metrics


def stratified_split(
    examples: Sequence[BaselineExample],
    train_ratio: float = 0.60,
    validation_ratio: float = 0.20,
    seed: int = 42,
) -> Tuple[List[BaselineExample], List[BaselineExample], List[BaselineExample]]:
    """Create deterministic stratified train, validation, and held-out test partitions."""
    if train_ratio <= 0 or validation_ratio <= 0 or train_ratio + validation_ratio >= 1:
        raise ValueError("train_ratio and validation_ratio must be positive and sum to less than one")

    examples_by_label: Dict[int, List[BaselineExample]] = {0: [], 1: []}
    for example in examples:
        if example.label not in examples_by_label:
            raise ValueError("Labels must be 0 (benign) or 1 (exfiltration)")
        examples_by_label[example.label].append(example)

    rng = random.Random(seed)
    training, validation, test = [], [], []
    for label_examples in examples_by_label.values():
        shuffled = list(label_examples)
        rng.shuffle(shuffled)
        train_end = int(len(shuffled) * train_ratio)
        validation_end = train_end + int(len(shuffled) * validation_ratio)
        training.extend(shuffled[:train_end])
        validation.extend(shuffled[train_end:validation_end])
        test.extend(shuffled[validation_end:])
    return training, validation, test


def load_baseline_examples(
    input_csv: Path,
    window_seconds: float = 60.0,
    max_rows: int | None = None,
) -> List[BaselineExample]:
    """Compute baseline inputs from a cleaned CSV without writing any output files."""
    if not input_csv.exists():
        raise FileNotFoundError(f"Input CSV does not exist: {input_csv}")

    with input_csv.open(encoding="utf-8", newline="") as input_file:
        reader = csv.DictReader(input_file)
        fieldnames = set(reader.fieldnames or ())
        if FEATURE_CSV_REQUIRED_COLUMNS.issubset(fieldnames):
            # Consume already-derived feature output directly. Extra columns,
            # including time_interval and Hero's other features, are ignored.
            examples = []
            for row_number, row in enumerate(reader):
                if max_rows is not None and row_number >= max_rows:
                    break
                examples.append(
                    BaselineExample(
                        features={name: float(row[name]) for name in BASELINE_FEATURE_NAMES},
                        label=int(float(row["label"])),
                    )
                )
            return examples

    # Preserve the original cleaned-dataset workflow when derived columns are
    # absent: normalize records and calculate the feature values in memory.
    pipeline = PreprocessingPipeline(check_duplicates=False)
    behavioral_extractor = BehavioralFeatureExtractor(window_seconds=window_seconds)
    examples = []
    with input_csv.open(encoding="utf-8", newline="") as input_file:
        for row_number, row in enumerate(csv.DictReader(input_file)):
            if max_rows is not None and row_number >= max_rows:
                break
            record = pipeline.normalize_and_parse_record(pipeline.parse_csv_row_to_raw_record(row))
            features = extract_per_query_features(record)
            features.update(behavioral_extractor.extract(record))
            examples.append(
                BaselineExample(
                    features={name: float(features[name]) for name in BASELINE_FEATURE_NAMES},
                    label=record.label,
                )
            )
    return examples
