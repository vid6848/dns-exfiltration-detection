
"""Export and plot feature importance from the latest saved Random Forest.

Reads the existing model and feature manifest. Does not retrain or modify
the model or Jaynish's existing experiment artifacts.
"""

import csv
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np

from src.ml.artifact import load_model


EXPERIMENT_DIR = Path("artifacts/aws_benign_expansion_v0.1")
MODEL_PATH = EXPERIMENT_DIR / "random_forest.joblib"
MANIFEST_PATH = EXPERIMENT_DIR / "feature_order.json"

OUTPUT_DIR = Path(
    "evaluation/results/baseline_vs_rf_v1/feature_importance"
)


def main() -> None:
    # 1. Confirm that the required inputs exist.
    for path in (MODEL_PATH, MANIFEST_PATH):
        if not path.is_file():
            raise FileNotFoundError(f"Required file not found: {path}")

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    feature_names = manifest.get("feature_order")

    if not isinstance(feature_names, list) or not feature_names:
        raise ValueError("Manifest must contain a non-empty feature_order list.")

    if len(feature_names) != len(set(feature_names)):
        raise ValueError("The feature manifest contains duplicate feature names.")

    # 2. Load the existing saved model.
    bundle = load_model(MODEL_PATH)
    model = bundle["model"]

    if not hasattr(model, "feature_importances_"):
        raise TypeError(
            "The saved estimator does not expose feature_importances_."
        )

    importances = np.asarray(model.feature_importances_, dtype=float)

    # 3. Verify the mapping and numeric values before plotting.
    if importances.ndim != 1 or len(importances) != len(feature_names):
        raise ValueError(
            f"Manifest has {len(feature_names)} features, but the model "
            f"has {len(importances)} importance values."
        )

    if hasattr(model, "n_features_in_"):
        if model.n_features_in_ != len(feature_names):
            raise ValueError("Model feature count does not match the manifest.")

    if not np.isfinite(importances).all() or (importances < 0).any():
        raise ValueError("Importances contain invalid or negative values.")

    importance_sum = float(importances.sum())

    if not np.isclose(importance_sum, 1.0, atol=1e-6):
        raise ValueError(
            f"Importances should sum to 1.0; found {importance_sum:.10f}."
        )

    # 4. Sort the results from most important to least important.
    ranked = sorted(
        zip(feature_names, importances.tolist()),
        key=lambda item: item[1],
        reverse=True,
    )

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # 5. Save a machine-readable CSV.
    csv_path = OUTPUT_DIR / "feature_importance.csv"

    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(
            ["rank", "feature", "importance", "importance_percent"]
        )

        for rank, (feature, value) in enumerate(ranked, start=1):
            writer.writerow(
                [rank, feature, f"{value:.10f}", f"{value * 100:.6f}"]
            )

    # 6. Save a JSON record with provenance and interpretation notes.
    json_path = OUTPUT_DIR / "feature_importance.json"

    report = {
        "model_artifact": str(MODEL_PATH),
        "feature_manifest": str(MANIFEST_PATH),
        "decision_threshold": manifest["decision_threshold"],
        "window_seconds": manifest["window_seconds"],
        "importance_method": (
            "Random Forest feature_importances_ "
            "(impurity-based global importance)"
        ),
        "interpretation_note": (
            "Importance is model-specific and global. It does not establish "
            "causality or explain an individual prediction. Correlated "
            "features may share or redistribute importance."
        ),
        "importance_sum": importance_sum,
        "features": [
            {
                "rank": rank,
                "feature": feature,
                "importance": value,
                "importance_percent": value * 100,
            }
            for rank, (feature, value) in enumerate(ranked, start=1)
        ],
    }

    json_path.write_text(
        json.dumps(report, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )

    # 7. Create a horizontal bar chart, highest importance at the top.
    plot_items = list(reversed(ranked))
    plot_names = [item[0] for item in plot_items]
    plot_values = [item[1] for item in plot_items]

    fig, ax = plt.subplots(figsize=(10, 6.5))
    bars = ax.barh(plot_names, plot_values)

    max_value = max(plot_values)
    ax.set_xlim(0, max_value * 1.23)

    for bar, value in zip(bars, plot_values):
        ax.text(
            value + max_value * 0.012,
            bar.get_y() + bar.get_height() / 2,
            f"{value * 100:.2f}%",
            va="center",
            fontsize=9,
        )

    ax.set_title("Random Forest Feature Importance")
    ax.set_xlabel("Impurity-based importance")
    ax.set_ylabel("DNS feature")
    ax.grid(axis="x", alpha=0.25)
    ax.set_axisbelow(True)

    fig.text(
        0.5,
        0.01,
        "Global model-level importance; not causality or a per-query explanation.",
        ha="center",
        fontsize=8,
    )

    fig.tight_layout(rect=(0, 0.05, 1, 1))

    plot_path = OUTPUT_DIR / "feature_importance.png"
    fig.savefig(plot_path, dpi=180)
    plt.close(fig)

    # 8. Print a concise verification summary.
    print("Feature-importance analysis completed successfully.")
    print(f"Model: {MODEL_PATH}")
    print(f"Features verified: {len(feature_names)}")
    print(f"Importance sum: {importance_sum:.8f}")
    print("\nRanked importance:")

    for rank, (feature, value) in enumerate(ranked, start=1):
        print(f"{rank:2}. {feature:28s} {value:.8f} ({value * 100:.2f}%)")

    print("\nSaved outputs:")
    print(f"  {plot_path}")
    print(f"  {csv_path}")
    print(f"  {json_path}")


if __name__ == "__main__":
    main()
