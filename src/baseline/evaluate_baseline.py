"""Command-line evaluation for the statistical DNS detection baseline."""

import argparse
from pathlib import Path

from src.baseline.detector import evaluate, load_baseline_examples, select_thresholds, stratified_split


def _print_metrics(title, metrics) -> None:
    print(title)
    print(f"  Accuracy:            {metrics.accuracy:.4f}")
    print(f"  Precision:           {metrics.precision:.4f}")
    print(f"  Recall:              {metrics.recall:.4f}")
    print(f"  F1-score:            {metrics.f1_score:.4f}")
    print(f"  False-positive rate: {metrics.false_positive_rate:.4f}")
    print(
        f"  TP={metrics.true_positives}, TN={metrics.true_negatives}, "
        f"FP={metrics.false_positives}, FN={metrics.false_negatives}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Tune and evaluate the DNS threshold baseline")
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/processed/cleaned_unified_v0.1.csv"),
        help="Cleaned input CSV; it is read only",
    )
    parser.add_argument("--window-seconds", type=float, default=60.0)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-candidates-per-feature", type=int, default=3)
    args = parser.parse_args()

    examples = load_baseline_examples(args.input, window_seconds=args.window_seconds)
    training, validation, test = stratified_split(examples, seed=args.seed)
    detector, validation_metrics = select_thresholds(
        training, validation, max_candidates_per_feature=args.max_candidates_per_feature
    )
    test_metrics = evaluate(detector, test)

    print(f"Loaded {len(examples)} examples (train={len(training)}, validation={len(validation)}, test={len(test)}).")
    print("Selected thresholds (training candidates; selected on validation):")
    for name, threshold in detector.config.as_dict().items():
        print(f"  {name}: >= {threshold:.6f}")
    print(f"  min_indicators: {detector.config.min_indicators}")
    _print_metrics("Validation selection metrics:", validation_metrics)
    _print_metrics("Held-out test metrics:", test_metrics)


if __name__ == "__main__":
    main()
