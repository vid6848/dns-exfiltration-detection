"""AWS expansion must not smuggle held-out domains through public data."""

import csv
import pytest

from src.ml.aws_generalization import filter_benign_capture, heldout_partition
from src.ml.data import Example
from src.preprocessing.pipeline import PreprocessingPipeline


def example(row_id, domain, label=0):
    pipeline = PreprocessingPipeline(check_duplicates=False)
    raw = pipeline.parse_csv_row_to_raw_record(dict(timestamp=str(1000+row_id),
        src_ip='192.0.2.1', dst_ip='192.0.2.53', requested_server_name=domain,
        query_type='A', label=label))
    return Example(row_id, pipeline.normalize_and_parse_record(raw))


def allocation(path, records, folds):
    with path.open('w', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['input_row_id', 'apex_domain', 'outer_fold', 'label'])
        writer.writerows((e.row_id, e.record.apex_domain, fold, e.record.label)
                         for e, fold in zip(records, folds))


def test_external_aws_and_other_evaluation_domains_are_excluded():
    records = [example(1, 'long.amazonaws.com'), example(2, 'cdn.example.org'),
               example(3, 'university.example.net')]
    accepted = filter_benign_capture(records, {'amazonaws.com', 'example.org'})
    assert [e.row_id for e in accepted] == [3]
    with pytest.raises(ValueError, match='non-benign'):
        filter_benign_capture([example(4, 'a.attack.com', 1)], set())


def test_frozen_allocation_keeps_aws_outside_training(tmp_path):
    records = [example(1, 'a.amazonaws.com'), example(2, 'b.amazonaws.com'),
               example(3, 'www.safe.org'), example(4, 'a.attack.net', 1)]
    path = tmp_path / 'allocation.csv'
    allocation(path, records, [4, 4, 0, 4])
    training, evaluation, excluded, _ = heldout_partition(records, path)
    assert [e.row_id for e in training] == [3]
    assert {e.row_id for e in evaluation} == {1, 2, 4}
    assert excluded == {'amazonaws.com', 'attack.net'}


def test_inconsistent_baseline_domain_allocation_is_rejected(tmp_path):
    records = [example(1, 'a.amazonaws.com'), example(2, 'b.amazonaws.com')]
    path = tmp_path / 'allocation.csv'
    allocation(path, records, [4, 0])
    with pytest.raises(ValueError, match='splits an apex'):
        heldout_partition(records, path)
