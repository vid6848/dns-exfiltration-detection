
"""Generate plots for the baseline-versus-Random-Forest evaluation.

Reads the existing evaluation JSON and saves plots separately.
Does not retrain the model or modify existing evaluation results.
"""

import json
from pathlib import Path

import matplotlib

# Save plots without requiring an interactive window.
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np


RESULTS_DIR = Path("evaluation/results/baseline_vs_rf_v1")
METRICS_PATH = RESULTS_DIR / "baseline_vs_rf_metrics.json"
PLOTS_DIR = RESULTS_DIR / "plots"


def load_metrics() -> tuple[dict, dict]:
    """Load and validate the saved comparison metrics."""
    if not METRICS_PATH.is_file():
        raise FileNotFoundError(
            f"Evaluation metrics not found: {METRICS_PATH}. "
            "Run scripts.evaluate_baseline_vs_rf first."
        )

    report = json.loads(METRICS_PATH.read_text(encoding="utf-8"))

    required_models = {"statistical_baseline", "random_forest"}
    missing = required_models - report.keys()

    if missing:
        raise ValueError(f"Metrics JSON is missing model sections: {missing}")

    baseline = report["statistical_baseline"]
    forest = report["random_forest"]

    required_metrics = {
        "precision",
        "recall",
        "f1",
        "false_positive_rate",
        "confusion_matrix",
    }

    for model_name, metrics in (
        ("statistical_baseline", baseline),
        ("random_forest", forest),
    ):
        missing_metrics = required_metrics - metrics.keys()
        if missing_metrics:
            raise ValueError(
                f"{model_name} is missing metrics: {missing_metrics}"
            )

        matrix = np.asarray(metrics["confusion_matrix"])

        if matrix.shape != (2, 2):
            raise ValueError(
                f"{model_name} confusion matrix must be 2x2."
            )

        if not np.isfinite(matrix).all() or (matrix < 0).any():
            raise ValueError(
                f"{model_name} confusion matrix contains invalid counts."
            )

    return baseline, forest


def plot_metric_comparison(baseline: dict, forest: dict) -> None:
    """Compare precision, recall and F1-score."""
    metric_names = ["Precision", "Recall", "F1-score"]
    keys = ["precision", "recall", "f1"]

    baseline_values = [baseline[key] * 100 for key in keys]
    forest_values = [forest[key] * 100 for key in keys]

    positions = np.arange(len(metric_names))
    width = 0.34

    fig, ax = plt.subplots(figsize=(9, 5.5))

    baseline_bars = ax.bar(
        positions - width / 2,
        baseline_values,
        width,
        label="Statistical baseline",
    )
    forest_bars = ax.bar(
        positions + width / 2,
        forest_values,
        width,
        label="Random Forest",
    )

    ax.bar_label(baseline_bars, fmt="%.2f%%", padding=3, fontsize=9)
    ax.bar_label(forest_bars, fmt="%.2f%%", padding=3, fontsize=9)

    ax.set_title("Statistical Baseline vs Random Forest")
    ax.set_ylabel("Score (%)")
    ax.set_xticks(positions, metric_names)
    ax.set_ylim(0, 112)
    ax.legend()
    ax.grid(axis="y", alpha=0.25)
    ax.set_axisbelow(True)

    fig.text(
        0.5,
        0.01,
        "Previously inspected diagnostic evaluation; not an independent final test.",
        ha="center",
        fontsize=8,
    )

    fig.tight_layout(rect=(0, 0.05, 1, 1))
    fig.savefig(PLOTS_DIR / "metric_comparison.png", dpi=180)
    plt.close(fig)


def plot_false_positive_rate(baseline: dict, forest: dict) -> None:
    """Compare false-positive rates on a dedicated scale."""
    names = ["Statistical baseline", "Random Forest"]
    values = [
        baseline["false_positive_rate"] * 100,
        forest["false_positive_rate"] * 100,
    ]

    fig, ax = plt.subplots(figsize=(8, 5))

    bars = ax.bar(names, values)
    ax.bar_label(bars, labels=[f"{value:.4f}%" for value in values], padding=4)

    ax.set_title("False-Positive Rate Comparison")
    ax.set_ylabel("False-positive rate (%)")
    ax.set_ylim(0, max(values) * 1.3 if max(values) > 0 else 1)
    ax.grid(axis="y", alpha=0.25)
    ax.set_axisbelow(True)

    fig.text(
        0.5,
        0.01,
        "Previously inspected diagnostic evaluation; not an independent final test.",
        ha="center",
        fontsize=8,
    )

    fig.tight_layout(rect=(0, 0.05, 1, 1))
    fig.savefig(PLOTS_DIR / "false_positive_rate_comparison.png", dpi=180)
    plt.close(fig)


def plot_confusion_matrix(
    metrics: dict,
    model_name: str,
    filename: str,
) -> None:
    """Plot counts in the matrix [[TN, FP], [FN, TP]]."""
    matrix = np.asarray(metrics["confusion_matrix"], dtype=np.int64)

    fig, ax = plt.subplots(figsize=(7, 5.5))

    image = ax.imshow(matrix)
    fig.colorbar(image, ax=ax, label="Number of records")

    # Explicit count annotations make the matrix interpretable without
    # relying on colour intensity alone.
    for row in range(2):
        for column in range(2):
            ax.text(
                column,
                row,
                f"{matrix[row, column]:,}",
                ha="center",
                va="center",
                fontsize=13,
            )

    ax.set_xticks([0, 1], ["Predicted benign", "Predicted suspicious"])
    ax.set_yticks([0, 1], ["Actual benign", "Actual exfiltration"])
    ax.set_xlabel("Predicted class")
    ax.set_ylabel("Actual class")
    ax.set_title(f"{model_name}\nDiagnostic Evaluation Confusion Matrix")

    fig.text(
        0.5,
        0.01,
        "Previously inspected diagnostic evaluation; not an independent final test.",
        ha="center",
        fontsize=8,
    )

    fig.tight_layout(rect=(0, 0.05, 1, 1))
    fig.savefig(PLOTS_DIR / filename, dpi=180)
    plt.close(fig)


def main() -> None:
    baseline, forest = load_metrics()
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)

    plot_metric_comparison(baseline, forest)
    plot_false_positive_rate(baseline, forest)

    plot_confusion_matrix(
        baseline,
        "Statistical Baseline",
        "confusion_matrix_baseline.png",
    )
    plot_confusion_matrix(
        forest,
        "Random Forest",
        "confusion_matrix_random_forest.png",
    )

    print("All evaluation plots generated successfully.")
    print(f"Source metrics: {METRICS_PATH}")
    print(f"Output directory: {PLOTS_DIR}")
    print("Generated plots:")
    for filename in (
        "metric_comparison.png",
        "false_positive_rate_comparison.png",
        "confusion_matrix_baseline.png",
        "confusion_matrix_random_forest.png",
    ):
        print(f"  - {filename}")


if __name__ == "__main__":
    main()
