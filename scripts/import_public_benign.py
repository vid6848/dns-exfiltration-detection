"""Convert a publisher-labelled benign PCAP prefix to canonical training input.

This imports ground truth from provenance, never from a model or name heuristic.
The packet cap is a contiguous prefix, chosen before looking at model scores.
"""

import argparse
import csv
from pathlib import Path

from scripts.probe_public_benign import read_benign_capture
from src.ml.train import sha256_file, write_json


def convert(pcap, output, publisher_file, max_packets=200000):
    if output.exists() or output.with_suffix('.provenance.json').exists():
        raise ValueError('Use a new output path to preserve imported data')
    examples, counts = read_benign_capture(pcap, max_packets=max_packets)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('w', encoding='utf-8', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['timestamp', 'src_ip', 'dst_ip', 'requested_server_name',
                         'query_type', 'label', 'source'])
        for example in examples:
            r = example.record
            writer.writerow([repr(r.epoch_time), r.src_ip, r.dst_ip,
                r.requested_server_name, r.query_type, 0, 'Daumel: ' + publisher_file])
    report = dict(publisher_file=publisher_file, source_url='https://www.kaggle.com/datasets/daumel/dns-tunneling-dataset',
        license='CC BY 4.0', label_basis='Publisher-labelled benign directory; no model-based labelling',
        capture_sha256=sha256_file(pcap), capture_bytes=pcap.stat().st_size,
        output_sha256=sha256_file(output), rows=len(examples), max_packets=max_packets,
        counts=counts, time_span_seconds=examples[-1].record.epoch_time-examples[0].record.epoch_time,
        distinct_apex_domains=len({e.record.apex_domain for e in examples}),
        selection='First fixed number of packets in file order; no score-based selection',
        limitations=['UDP single-question DNS only; no fragment/TCP reassembly',
                     'Capture prefix starts with fresh behavioral history',
                     'Publisher labels are not independently verified'])
    write_json(output.with_suffix('.provenance.json'), report)
    print(report, flush=True)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pcap', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--publisher-file', required=True)
    parser.add_argument('--max-packets', type=int, default=200000)
    args = parser.parse_args()
    convert(args.pcap, args.output, args.publisher_file, args.max_packets)


if __name__ == '__main__':
    main()
