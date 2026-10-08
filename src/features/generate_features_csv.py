import csv
import sys
from pathlib import Path
from src.preprocessing.pipeline import PreprocessingPipeline
from src.features.per_query import extract_per_query_features, FEATURE_NAMES
from src.features.behavioral import BehavioralFeatureExtractor, BEHAVIORAL_FEATURE_NAMES

def generate_features_csv(
    input_csv: Path,
    output_csv: Path,
    window_seconds: float = 60.0,
) -> int:
    """Append per-query and behavioral features to a cleaned chronological CSV."""
    
    pipeline = PreprocessingPipeline(check_duplicates=False)
    
    # We will read the cleaned dataset, which has already been exported by the pipeline,
    # and map each row back to a NormalizedRecord. The PreprocessingPipeline has 
    # parse_csv_row_to_raw_record -> normalize_and_parse_record, but since the CSV is already cleaned,
    # we can process it by loading it as raw records and applying normalize again. 
    # Let's do it safely:
    
    if not input_csv.exists():
        raise FileNotFoundError(f"Input CSV does not exist: {input_csv}")
        
    # We want to keep all original columns and append the feature columns.
    with open(input_csv, "r", encoding="utf-8") as fin:
        reader = csv.DictReader(fin)
        fieldnames = list(reader.fieldnames)
        
        # Add only derived numeric features. Grouping keys and temporal anchors
        # remain source columns and are not copied into the feature set.
        out_fieldnames = fieldnames.copy()
        for f in FEATURE_NAMES + BEHAVIORAL_FEATURE_NAMES:
            if f not in out_fieldnames:
                out_fieldnames.append(f)
                
        with open(output_csv, "w", encoding="utf-8", newline="") as fout:
            writer = csv.DictWriter(fout, fieldnames=out_fieldnames)
            writer.writeheader()
            behavioral_extractor = BehavioralFeatureExtractor(window_seconds)
            row_count = 0
            for row in reader:
                # Convert the cleaned CSV row to RawRecord and then to NormalizedRecord
                # Because the cleaned CSV was exported by PreprocessingPipeline, it has the standard fields.
                # Let's map it safely.
                raw_rec = pipeline.parse_csv_row_to_raw_record(row)
                
                # The normalizer expects a raw_rec.
                # However, parse_csv_row_to_raw_record sets the label, IP, etc.
                norm_rec = pipeline.normalize_and_parse_record(raw_rec)
                
                features = extract_per_query_features(norm_rec)
                features.update(behavioral_extractor.extract(norm_rec))
                
                # Update row with features
                out_row = row.copy()
                for k, v in features.items():
                    out_row[k] = v
                
                writer.writerow(out_row)
                row_count += 1
    return row_count


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Generate DNS per-query and behavioral features")
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/processed/cleaned_unified_v0.1.csv"),
        help="Chronologically sorted cleaned input CSV",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/processed/feature_enriched_behavioral_v0.1.csv"),
        help="CSV path for enriched output",
    )
    parser.add_argument(
        "--window-seconds",
        type=float,
        default=60.0,
        help="Inclusive behavioral sliding-window duration (default: 60)",
    )
    args = parser.parse_args()

    print(f"Reading from {args.input} ...")
    if not args.input.exists():
        print(f"Error: {args.input} does not exist.")
        sys.exit(1)

    row_count = generate_features_csv(args.input, args.output, args.window_seconds)
    print(f"Processed {row_count} rows. Enriched dataset written to {args.output}.")

if __name__ == "__main__":
    main()
