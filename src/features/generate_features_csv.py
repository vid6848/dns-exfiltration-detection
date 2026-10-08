import csv
import sys
from pathlib import Path
from src.preprocessing.pipeline import PreprocessingPipeline
from src.features.per_query import extract_per_query_features, FEATURE_NAMES

def main():
    input_csv = Path("data/processed/cleaned_unified_v0.1.csv")
    output_csv = Path("data/processed/feature_enriched_v0.1.csv")
    
    pipeline = PreprocessingPipeline(check_duplicates=False)
    
    # We will read the cleaned dataset, which has already been exported by the pipeline,
    # and map each row back to a NormalizedRecord. The PreprocessingPipeline has 
    # parse_csv_row_to_raw_record -> normalize_and_parse_record, but since the CSV is already cleaned,
    # we can process it by loading it as raw records and applying normalize again. 
    # Let's do it safely:
    
    print(f"Reading from {input_csv} ...")
    if not input_csv.exists():
        print(f"Error: {input_csv} does not exist.")
        sys.exit(1)
        
    records = []
    
    # We want to keep all original columns and append the feature columns.
    with open(input_csv, "r", encoding="utf-8") as fin:
        reader = csv.DictReader(fin)
        fieldnames = list(reader.fieldnames)
        
        # Ensure we add our FEATURE_NAMES
        out_fieldnames = fieldnames.copy()
        for f in FEATURE_NAMES:
            if f not in out_fieldnames:
                out_fieldnames.append(f)
                
        with open(output_csv, "w", encoding="utf-8", newline="") as fout:
            writer = csv.DictWriter(fout, fieldnames=out_fieldnames)
            writer.writeheader()
            
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
                
                # Update row with features
                out_row = row.copy()
                for k, v in features.items():
                    out_row[k] = v
                
                writer.writerow(out_row)
                row_count += 1
                
    print(f"Processed {row_count} rows. Enriched dataset written to {output_csv}.")

if __name__ == "__main__":
    main()
