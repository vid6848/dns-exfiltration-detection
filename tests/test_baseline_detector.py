from pathlib import Path

import pytest

from src.baseline.detector import (
    BASELINE_FEATURE_NAMES,
    BaselineDetector,
    BaselineExample,
    ThresholdConfig,
    evaluate,
    load_baseline_examples,
    select_thresholds,
    stratified_split,
)
from src.preprocessing.schema import verify_ml_feature_safety


def example(label, query_length, entropy, query_frequency, unique_subdomains):
    return BaselineExample(
        {
            "query_length": query_length,
            "entropy": entropy,
            "query_frequency": query_frequency,
            "unique_subdomains": unique_subdomains,
        },
        label,
    )


def test_detector_requires_the_configured_number_of_indicators():
    detector = BaselineDetector(ThresholdConfig(40, 4.0, 5, 5, min_indicators=2))
    assert detector.predict(example(0, 45, 4.2, 1, 1).features) == 1
    assert detector.predict(example(0, 45, 3.0, 1, 1).features) == 0


def test_evaluation_reports_confusion_matrix_and_metrics():
    detector = BaselineDetector(ThresholdConfig(40, 4.0, 5, 5, min_indicators=1))
    examples = [
        example(1, 45, 1, 1, 1),  # TP
        example(0, 20, 1, 1, 1),  # TN
        example(0, 45, 1, 1, 1),  # FP
        example(1, 20, 1, 1, 1),  # FN
    ]

    metrics = evaluate(detector, examples)

    assert (metrics.true_positives, metrics.true_negatives, metrics.false_positives, metrics.false_negatives) == (1, 1, 1, 1)
    assert metrics.accuracy == pytest.approx(0.5)
    assert metrics.precision == pytest.approx(0.5)
    assert metrics.recall == pytest.approx(0.5)
    assert metrics.f1_score == pytest.approx(0.5)
    assert metrics.false_positive_rate == pytest.approx(0.5)


def test_threshold_selection_uses_only_the_given_training_and_validation_sets():
    training = [
        example(0, 10, 1, 1, 1),
        example(0, 12, 1, 1, 1),
        example(1, 100, 6, 10, 10),
        example(1, 110, 7, 11, 11),
    ]
    validation = [
        example(0, 11, 1, 1, 1),
        example(1, 105, 6, 10, 10),
    ]

    detector, metrics = select_thresholds(training, validation, max_candidates_per_feature=2)

    assert detector.predict(validation[0].features) == 0
    assert detector.predict(validation[1].features) == 1
    assert metrics.f1_score == 1.0


def test_stratified_split_is_deterministic_and_preserves_every_example():
    examples = [example(0, 10, 1, 1, 1) for _ in range(10)] + [example(1, 100, 6, 10, 10) for _ in range(10)]
    first_split = stratified_split(examples, seed=7)
    second_split = stratified_split(examples, seed=7)

    assert first_split == second_split
    assert [len(partition) for partition in first_split] == [12, 4, 4]
    for partition in first_split:
        assert sum(item.label for item in partition) == len(partition) // 2


def test_baseline_features_are_safe_derived_features():
    verify_ml_feature_safety(BASELINE_FEATURE_NAMES)


def test_loader_reads_the_actual_cleaned_dataset_without_writing():
    # A small read from the project dataset verifies the integration path while
    # keeping the unit suite quick and leaving all project data untouched.
    examples = load_baseline_examples(Path("data/processed/cleaned_unified_v0.1.csv"), max_rows=3)

    assert len(examples) == 3
    assert all(set(item.features) == set(BASELINE_FEATURE_NAMES) for item in examples)


def test_loader_consumes_existing_derived_feature_columns():
    feature_csv = Path("tests/.baseline_derived_feature_input.csv")
    feature_csv.write_text(
        "query_length,entropy,query_frequency,unique_subdomains,time_interval,label,src_ip\n"
        "42,4.5,3,2,-1.0,1,10.0.0.1\n",
        encoding="utf-8",
    )
    try:
        examples = load_baseline_examples(feature_csv)
    finally:
        feature_csv.unlink(missing_ok=True)

    assert examples[0].features == {
        "query_length": 42.0,
        "entropy": 4.5,
        "query_frequency": 3.0,
        "unique_subdomains": 2.0,
    }
    assert examples[0].label == 1
