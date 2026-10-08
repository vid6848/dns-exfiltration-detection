"""The optional public-data reader must preserve causal query semantics."""

import numpy as np
import pytest

pytest.importorskip('scapy')
from scapy.all import DNS, DNSQR, IP, UDP, TCP, wrpcap

from scripts.probe_public_benign import read_benign_capture, benign_metrics
from src.ml.data import derive_features


def packet(name, time, *, response=False, tcp=False):
    transport = TCP(dport=53) if tcp else UDP(dport=53)
    result = IP(src='192.0.2.1', dst='192.0.2.53') / transport / DNS(
        qr=int(response), qd=DNSQR(qname=name))
    result.time = time
    return result


def test_capture_query_filtering_and_causal_order(tmp_path):
    path = tmp_path / 'benign.pcap'
    wrpcap(str(path), [packet('second.example.org.', 1002),
                      packet('first.example.org.', 1000),
                      packet('response.example.org.', 1001, response=True),
                      packet('tcp.example.org.', 1001, tcp=True),
                      packet('first.example.org.', 1000)])
    records, counts = read_benign_capture(path)
    assert [e.record.requested_server_name for e in records] == [
        'first.example.org', 'second.example.org']
    assert counts['non_query_packets'] == 1
    assert counts['unsupported_transport'] == 1
    assert counts['duplicate_events'] == 1
    rows, _, _ = derive_features(records)
    assert rows[0]['time_interval'] == -1.0
    assert rows[1]['time_interval'] == 2.0
    assert rows[1]['query_frequency'] == 2
    assert rows[1]['unique_subdomains'] == 2


def test_empty_unseen_subset_has_no_estimated_fpr():
    result = benign_metrics(np.array([1, 0]), np.array([False, False]))
    assert result == dict(queries=0, false_positives=0, false_positive_rate=None)
