"""Fast-burst remediation: generator timing, leakage guards and re-timing."""

from datetime import datetime

import pytest

from data.generate_synthetic_exfiltration import generate_synthetic_dataset
from src.ml.data import Example
from src.ml.fast_burst import load_attack_capture, retime
from src.preprocessing.pipeline import PreprocessingPipeline


def _gaps_ms(records):
    last, gaps = {}, []
    for r in records:
        key = (r["src_ip"], r["requested_server_name"].split(".", 1)[-1])
        t = datetime.strptime(r["timestamp"], "%Y-%m-%d %H:%M:%S.%f")
        if key in last:
            gaps.append((t - last[key]).total_seconds() * 1000)
        last[key] = t
    return gaps


def test_default_generation_is_unchanged_by_the_new_mode():
    default, meta = generate_synthetic_dataset(500, seed=42)
    explicit, _ = generate_synthetic_dataset(500, seed=42, timing_modes=["burst", "low_and_slow"])
    assert default == explicit
    assert meta["timing_modes"] == ["burst", "low_and_slow"]


def test_fast_burst_campaigns_send_queries_under_50ms_apart():
    records, meta = generate_synthetic_dataset(400, seed=7, timing_modes=["fast_burst"],
                                               base_domains=["quick-test.net"], src_ips=["10.9.9.9"])
    assert meta["profiles"]["timing_fast_burst"] == 400
    # One client and one domain: every gap is between two queries of the same group.
    gaps = _gaps_ms(records)
    assert gaps and max(gaps) <= 50.0 + 1e-6


def test_unknown_timing_mode_is_rejected():
    with pytest.raises(ValueError, match="Unknown timing modes"):
        generate_synthetic_dataset(10, timing_modes=["warp"])


def _example(row_id, domain, epoch, label=1, src="10.0.0.5"):
    pipeline = PreprocessingPipeline(check_duplicates=False)
    raw = pipeline.parse_csv_row_to_raw_record(dict(timestamp=str(epoch), src_ip=src, dst_ip="192.0.2.53",
                                                    requested_server_name=domain, query_type="A", label=label))
    return Example(row_id, pipeline.normalize_and_parse_record(raw))


def test_attack_capture_may_not_reuse_evaluation_domains(tmp_path):
    path = tmp_path / "attacks.csv"
    path.write_text("timestamp,src_ip,dst_ip,requested_server_name,label\n"
                    "1000,10.0.0.5,8.8.8.8,abc123.data-relay.info,1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="reuses evaluation domains"):
        load_attack_capture(path, {"data-relay.info"})
    benign = tmp_path / "benign.csv"
    benign.write_text("timestamp,src_ip,dst_ip,requested_server_name,label\n"
                      "1000,10.0.0.5,8.8.8.8,www.example.org,0\n", encoding="utf-8")
    with pytest.raises(ValueError, match="non-attack"):
        load_attack_capture(benign, set())


def test_retime_sets_a_fixed_gap_per_group_and_keeps_order():
    examples = [_example(1, "a1.x-tunnel.net", 100.0), _example(2, "a2.x-tunnel.net", 107.0),
                _example(3, "b1.y-tunnel.net", 101.0, src="10.0.0.6"), _example(4, "a3.x-tunnel.net", 150.0)]
    timed = retime(examples, 0.005)
    by_id = {e.row_id: e.record.epoch_time for e in timed}
    assert by_id[2] - by_id[1] == pytest.approx(0.005, abs=1e-6)
    assert by_id[4] - by_id[2] == pytest.approx(0.005, abs=1e-6)
    assert by_id[3] == by_id[1]  # other group starts its own clock
    assert [e.record.epoch_time for e in timed] == sorted(e.record.epoch_time for e in timed)
