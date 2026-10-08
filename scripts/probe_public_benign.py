"""Evaluate a publisher-labelled benign UDP DNS capture without fitting a model.

No download or traffic generation occurs here. Supply a trusted benign capture;
the script does not infer its ground truth from packet contents.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
from pathlib import Path

import numpy as np
from scapy.all import DNS, IP, IPv6, UDP, PcapReader

from src.ml.artifact import load_model, predict_features
from src.ml.data import Example, derive_features, load_records
from src.ml.features import FEATURE_ORDER
from src.ml.train import sha256_file, write_json
from src.preprocessing.pipeline import PreprocessingPipeline
from src.preprocessing.validator import validate_raw_record


def read_benign_capture(path):
    pipeline = PreprocessingPipeline(check_duplicates=False)
    records, seen, counts = [], set(), Counter()
    with PcapReader(str(path)) as packets:
        for packet_number, packet in enumerate(packets, start=1):
            counts['packets'] += 1
            if DNS not in packet or packet[DNS].qr != 0:
                counts['non_query_packets'] += 1
                continue
            counts['dns_query_packets'] += 1
            if UDP not in packet:
                counts['unsupported_transport'] += 1
                continue
            dns = packet[DNS]
            network = packet.getlayer(IP) or packet.getlayer(IPv6)
            if network is None or int(dns.qdcount) != 1 or not dns.qd:
                counts['unsupported_question_or_network'] += 1
                continue
            try:
                question = dns.qd[0]
                raw = pipeline.parse_csv_row_to_raw_record(dict(
                    timestamp=datetime.fromtimestamp(float(packet.time), timezone.utc).isoformat(),
                    src_ip=network.src, dst_ip=network.dst,
                    requested_server_name=question.qname.decode('ascii'),
                    query_type=str(int(question.qtype)), label=0,
                    source='Daumel publisher-labelled benign PCAP',
                ))
                valid, reason = validate_raw_record(raw)
                if not valid:
                    counts['invalid_records'] += 1
                    continue
                record = pipeline.normalize_and_parse_record(raw)
            except (ValueError, UnicodeError, TypeError):
                counts['invalid_records'] += 1
                continue
            key = (record.epoch_time, record.src_ip, record.dst_ip,
                   record.requested_server_name, record.query_type)
            if key in seen:
                counts['duplicate_events'] += 1
                continue
            seen.add(key)
            records.append(Example(packet_number, record))
    if not records:
        raise ValueError('No supported valid DNS queries in capture')
    records.sort(key=lambda e: (e.record.epoch_time, e.row_id))
    return records, dict(counts)


def benign_metrics(predictions, mask):
    count = int(np.sum(mask))
    false_positives = int(np.sum(predictions[mask]))
    return dict(queries=count, false_positives=false_positives,
                false_positive_rate=false_positives / count if count else None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pcap', type=Path, required=True)
    parser.add_argument('--publisher-file', default='dns-exfiltration-dataset/01_original_pcap_files/benign/top_1_million_domains/normal_00000_20230805150331.pcap')
    parser.add_argument('--model', type=Path, default=Path('artifacts/random_forest_v0.2/random_forest.joblib'))
    parser.add_argument('--development', type=Path, default=Path('data/processed/cleaned_unified_v0.1.csv'))
    parser.add_argument('--output', type=Path, default=Path('artifacts/public_benign_probe/experiment.json'))
    args = parser.parse_args()
    records, counts = read_benign_capture(args.pcap)
    feature_rows, _, _ = derive_features(records)
    bundle = load_model(args.model)
    predictions, probabilities = predict_features(bundle, feature_rows)
    development, _ = load_records(args.development)
    known = {e.record.apex_domain for e in development}
    domains = np.array([e.record.apex_domain for e in records])
    unseen = np.array([domain not in known for domain in domains])
    report = dict(
        source=dict(url='https://www.kaggle.com/datasets/daumel/dns-tunneling-dataset',
                    repository='https://github.com/Daumel/dns-exfiltration-dataset',
                    publisher_file=args.publisher_file,
                    license='CC BY 4.0', capture_sha256=sha256_file(args.pcap),
                    capture_bytes=args.pcap.stat().st_size, label_basis='Publisher benign directory; not independently relabelled'),
        model=dict(sha256=sha256_file(args.model), threshold=bundle['decision_threshold']),
        development_sha256=sha256_file(args.development),
        feature_order=list(FEATURE_ORDER), ingestion=counts,
        all_queries=benign_metrics(predictions, np.ones(len(records), dtype=bool)),
        unseen_apex_queries=benign_metrics(predictions, unseen),
        distinct_apex_domains=len(set(domains)), unseen_apex_domains=len(set(domains[unseen])),
        probability_quantiles={str(q): float(np.quantile(probabilities, q)) for q in (0, .5, .95, 1)},
        false_positive_examples=[dict(domain=e.record.requested_server_name,
            probability=float(p), features=f) for e, p, f, y in
            zip(records, probabilities, feature_rows, predictions) if y][:10],
        limitations=['Single small generated top-domain benign capture; not representative of cloud/CDN bursts.',
                     'Benign-only probe: cannot measure attack recall or overall classifier accuracy.',
                     'UDP single-question DNS only; no TCP or IP fragment reassembly.',
                     'Fresh behavioral history at the capture boundary; publisher sample may split longer sessions.',
                     'No training or threshold changes made using probe scores.'],
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_json(args.output, report)
    print(json.dumps({k: report[k] for k in ('all_queries', 'unseen_apex_queries', 'distinct_apex_domains', 'unseen_apex_domains', 'ingestion')}, indent=2))


if __name__ == '__main__':
    main()
