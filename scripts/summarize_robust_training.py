"""Render a readable v0.2 report and verify saved experiment evidence."""

import argparse
import csv
import json
from pathlib import Path

from src.ml.artifact import load_model
from src.ml.features import FEATURE_ORDER
from src.ml.train import sha256_file, write_json


def summarize(directory):
    log = json.loads((directory / "experiment.json").read_text(encoding="utf-8"))
    bundle = load_model(directory / "random_forest.joblib")
    assignments, row_ids = {}, set()
    with (directory / "nested_predictions.csv").open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            row_id = int(row["input_row_id"])
            if row_id in row_ids:
                raise AssertionError("Duplicate nested prediction row")
            row_ids.add(row_id)
            assignments.setdefault(row["apex_domain"], set()).add(row["outer_fold"])
    checks = dict(
        input_sha256_matches=sha256_file(Path(log["input"]["path"])) == log["input"]["sha256"],
        source_sha256_matches=all(sha256_file(Path(path)) == digest
            for path, digest in log["source"]["file_sha256"].items()),
        model_sha256_matches=sha256_file(directory / "random_forest.joblib") == log["artifacts"]["model_sha256"],
        feature_order_matches=tuple(bundle["feature_order"]) == FEATURE_ORDER,
        all_rows_evaluated_once=len(row_ids) == log["input"]["rows"],
        no_outer_domain_overlap=all(len(folds) == 1 for folds in assignments.values()),
        selected_policy_met=log["final_model"]["selection"]["validation"]["pooled"]["false_positive_rate"] <= log["protocol"]["max_validation_fpr"]
            and log["final_model"]["selection"]["validation"]["worst_large_domain_fpr"] <= log["protocol"]["max_large_domain_fpr"],
        artifact_roundtrip=log["artifacts"]["roundtrip_probabilities_identical"],
    )
    if not all(checks.values()):
        raise AssertionError(checks)
    write_json(directory / "verification.json", checks)
    nested = log["nested_evaluation"]
    final = log["final_model"]["selection"]
    lines = ["# Random Forest v0.2 development results", "",
        "The original v0.1 experiment is preserved. Its already-inspected test",
        "records are now development data. Results below are nested domain-CV",
        "estimates of the selection workflow, not an independent final test of",
        "the saved all-development-data-refitted model.", "",
        "## Nested domain-disjoint evaluation", "",
        "| Outer fold | Rows | Domains | FPR | Recall | F1 | Selected threshold |",
        "|---|---:|---:|---:|---:|---:|---:|"]
    for fold in nested["folds"]:
        m = fold["metrics"]
        lines.append(f"| {fold['fold'] + 1} | {fold['evaluation_rows']:,} | {fold['evaluation_domains']} | {m['false_positive_rate']:.6f} | {m['recall']:.6f} | {m['f1']:.6f} | {fold['selection']['decision_threshold']} |")
    lines += ["", "Pooled outer-fold metrics:", ""]
    for name in ("accuracy", "precision", "recall", "f1", "false_positive_rate"):
        lines.append(f"- {name}: {nested['pooled'][name]:.6f}")
    lines.append("- TP/TN/FP/FN: " + " / ".join(str(nested["pooled"][k]) for k in ("tp", "tn", "fp", "fn")))
    aws = next((d for d in nested["domain_metrics"] if d["apex_domain"] == "amazonaws.com"), None)
    if aws:
        lines += ["", "## AWS benign-domain diagnostic", "",
            f"All {aws['benign']:,} AWS benign records were scored by an outer model",
            "whose training and inner selection excluded the entire AWS apex domain.",
            f"False positives: {aws['false_positives']:,}; FPR: {aws['false_positive_rate']:.6f}.",
            "The original v0.1 AWS FPR was 0.996194. The training population and",
            "selection protocol differ here, and development choices were informed",
            "by inspecting v0.1; this comparison is diagnostic, not a fresh test claim."]
    lines += ["", "## Final saved model", "",
        f"- Decision threshold: {final['decision_threshold']}.",
        f"- Parameters: `{json.dumps(final['parameters'], sort_keys=True)}`.",
        f"- Final selection pooled validation FPR: {final['validation']['pooled']['false_positive_rate']:.6f}.",
        f"- Worst large-domain validation FPR: {final['validation']['worst_large_domain_fpr']:.6f}.",
        "- Refit on all current development records, including existing AWS benign data.",
        "- Exact ten-feature order and shared feature semantics retained.",
        "- No independent final test available; artifact marked deployment_ready=False.",
        "", "## Verification and limits", "",
        "Checks passed for input/source/model hashes, feature order, complete",
        "row coverage, domain separation, validation policy, and artifact reload.",
        "See verification.json for checks and experiment.json for every selection trial.",
        "No new real benign captures or independent attack recordings were added.",
        "Unseen cloud/CDN families, parser grouping limits, and the small synthetic",
        "attack-domain pool remain relevant limitations. Collect fresh independent",
        "traffic before making final generalization or deployment claims.", ""]
    (directory / "RESULTS.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps(checks, indent=2))
    print("Nested pooled metrics:", nested["pooled"])
    print("AWS:", aws)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-dir", type=Path, default=Path("artifacts/random_forest_v0.2"))
    summarize(parser.parse_args().experiment_dir)
