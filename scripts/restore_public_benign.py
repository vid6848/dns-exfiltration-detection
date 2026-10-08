"""Restore the exact published benign development input without a large download."""

import argparse
import gzip
import json
from pathlib import Path
import shutil

from src.ml.train import sha256_file


def restore(archive, provenance_path, output):
    sidecar = output.with_suffix('.provenance.json')
    partial = output.with_suffix('.partial')
    if any(p.exists() for p in (output, sidecar, partial)):
        raise ValueError('Use a new output path; existing input evidence is preserved')
    provenance = json.loads(provenance_path.read_text(encoding='utf-8'))
    output.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(archive, 'rb') as source, partial.open('wb') as destination:
        shutil.copyfileobj(source, destination)
    if sha256_file(partial) != provenance['output_sha256']:
        partial.unlink()
        raise ValueError('Archive contents do not match publisher-import provenance')
    partial.replace(output)
    shutil.copyfile(provenance_path, sidecar)
    print(f'Restored {output}; SHA256 verified')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, default=Path('artifacts/aws_benign_expansion_v0.1/public_benign.csv.gz'))
    parser.add_argument('--provenance', type=Path, default=Path('artifacts/aws_benign_expansion_v0.1/public_benign.provenance.json'))
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    restore(args.archive, args.provenance, args.output)
