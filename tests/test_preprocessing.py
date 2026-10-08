"""
Comprehensive Unit Tests for CyberTrace Preprocessing and Parsing Module
Project: DNS Exfiltration Detection Using Network Traffic Analysis (CE305/CS305)

Owner: Yash (Preprocessing and Parsing)
"""

from datetime import datetime, timezone
import io
import unittest
from pathlib import Path

from src.preprocessing.schema import (
    DISALLOWED_RAW_ML_FEATURES,
    DataLeakageError,
    verify_ml_feature_safety,
    RawRecord,
    NormalizedRecord,
)
from src.preprocessing.normalizer import (
    normalize_domain,
    is_valid_fqdn,
)
from src.preprocessing.parser import (
    parse_domain_labels,
    DomainComponents,
)
from src.preprocessing.timestamps import (
    parse_timestamp,
    format_timestamp_standard,
    to_epoch_seconds,
    sort_records_chronologically,
)
from src.preprocessing.validator import (
    is_valid_ip,
    validate_raw_record,
    DatasetValidator,
)
from src.preprocessing.pipeline import PreprocessingPipeline


class TestDomainNormalization(unittest.TestCase):
    """Tests for normalizer.py."""

    def test_case_folding(self):
        self.assertEqual(normalize_domain("ExAmPLe.CoM"), "example.com")
        self.assertEqual(normalize_domain("UPPERCASE.NET"), "uppercase.net")

    def test_trailing_dot_stripping(self):
        self.assertEqual(normalize_domain("example.com."), "example.com")
        self.assertEqual(normalize_domain("sub.domain.org..."), "sub.domain.org")

    def test_whitespace_and_quote_stripping(self):
        self.assertEqual(normalize_domain("   example.com   "), "example.com")
        self.assertEqual(normalize_domain('"test.com"'), "test.com")
        self.assertEqual(normalize_domain("'test.com'"), "test.com")

    def test_scheme_and_url_sanitization(self):
        self.assertEqual(normalize_domain("http://sub.example.com"), "sub.example.com")
        self.assertEqual(normalize_domain("https://sub.example.com/api/v1?token=123"), "sub.example.com")
        self.assertEqual(normalize_domain("sub.example.com:8080"), "sub.example.com")
        self.assertEqual(normalize_domain("sub.example.com:53"), "sub.example.com")

    def test_valid_fqdn_rfc_rules(self):
        valid, _ = is_valid_fqdn("sub.example.com")
        self.assertTrue(valid)

        # Reverse DNS pointer
        valid, _ = is_valid_fqdn("8.8.8.8.in-addr.arpa")
        self.assertTrue(valid)

        # Internal cloud domain
        valid, _ = is_valid_fqdn("dimplesonmywhat.com.sa-east-1.compute.internal")
        self.assertTrue(valid)

    def test_invalid_fqdn_edge_cases(self):
        # Empty
        valid, _ = is_valid_fqdn("")
        self.assertFalse(valid)

        # Single label
        valid, _ = is_valid_fqdn("localhost")
        self.assertFalse(valid)

        # Empty label (consecutive dots)
        valid, _ = is_valid_fqdn("sub..example.com")
        self.assertFalse(valid)

        # Label exceeding 63 chars
        long_label = "a" * 64 + ".example.com"
        valid, _ = is_valid_fqdn(long_label)
        self.assertFalse(valid)

        # Total domain exceeding 253 chars
        long_domain = ("abc." * 65) + "com"
        valid, _ = is_valid_fqdn(long_domain)
        self.assertFalse(valid)

        # Hyphen at start or end of label
        valid, _ = is_valid_fqdn("-sub.example.com")
        self.assertFalse(valid)
        valid, _ = is_valid_fqdn("sub-.example.com")
        self.assertFalse(valid)


class TestDomainParser(unittest.TestCase):
    """Tests for parser.py."""

    def test_standard_two_label_domain(self):
        comp = parse_domain_labels("example.com")
        self.assertEqual(comp.labels, ["example", "com"])
        self.assertEqual(comp.label_count, 2)
        self.assertEqual(comp.tld, "com")
        self.assertEqual(comp.apex_domain, "example.com")
        self.assertEqual(comp.subdomain, "")
        self.assertEqual(comp.subdomain_length, 0)
        self.assertEqual(comp.longest_label, "example")
        self.assertEqual(comp.longest_label_length, 7)

    def test_multi_level_subdomains(self):
        comp = parse_domain_labels("s.wphamt5t5bjr6k2pwa32h2u4.data-relay.info")
        self.assertEqual(comp.label_count, 4)
        self.assertEqual(comp.tld, "info")
        self.assertEqual(comp.apex_domain, "data-relay.info")
        self.assertEqual(comp.subdomain, "s.wphamt5t5bjr6k2pwa32h2u4")
        self.assertEqual(comp.subdomain_labels, ["s", "wphamt5t5bjr6k2pwa32h2u4"])
        self.assertEqual(comp.subdomain_length, 26)
        self.assertEqual(comp.longest_label, "wphamt5t5bjr6k2pwa32h2u4")
        self.assertEqual(comp.longest_label_length, 24)

    def test_multi_part_public_suffix(self):
        comp = parse_domain_labels("portal.acme.co.uk")
        self.assertEqual(comp.tld, "co.uk")
        self.assertEqual(comp.apex_domain, "acme.co.uk")
        self.assertEqual(comp.subdomain, "portal")
        self.assertEqual(comp.label_count, 4)

    def test_reverse_dns_and_internal_cloud(self):
        comp = parse_domain_labels("8.8.8.8.in-addr.arpa")
        self.assertEqual(comp.tld, "in-addr.arpa")
        self.assertEqual(comp.apex_domain, "8.in-addr.arpa")
        self.assertEqual(comp.subdomain, "8.8.8")


class TestTimestampHandling(unittest.TestCase):
    """Tests for timestamps.py."""

    def test_parse_standard_millis_format(self):
        dt = parse_timestamp("2025-06-13 09:31:25.564")
        self.assertEqual(dt.year, 2025)
        self.assertEqual(dt.month, 6)
        self.assertEqual(dt.day, 13)
        self.assertEqual(dt.hour, 9)
        self.assertEqual(dt.minute, 31)
        self.assertEqual(dt.second, 25)
        self.assertEqual(dt.microsecond, 564000)

    def test_parse_iso8601_format(self):
        dt = parse_timestamp("2025-06-13T09:31:25.123Z")
        self.assertEqual(dt.year, 2025)
        self.assertEqual(dt.tzinfo, timezone.utc)

    def test_parse_epoch_timestamp(self):
        # 1750000000 in seconds
        dt = parse_timestamp(1750000000.5)
        self.assertEqual(dt.tzinfo, timezone.utc)
        self.assertAlmostEqual(to_epoch_seconds(dt), 1750000000.5, places=3)

    def test_format_timestamp_standard(self):
        dt = datetime(2025, 6, 13, 9, 31, 25, 564000, tzinfo=timezone.utc)
        formatted = format_timestamp_standard(dt)
        self.assertEqual(formatted, "2025-06-13 09:31:25.564")

    def test_chronological_sorting(self):
        dt1 = parse_timestamp("2025-06-13 10:00:00.000")
        dt2 = parse_timestamp("2025-06-13 09:00:00.000")
        dt3 = parse_timestamp("2025-06-13 11:00:00.000")

        r1 = NormalizedRecord(
            src_ip="10.0.0.1", dst_ip="8.8.8.8", requested_server_name="a.com",
            apex_domain="a.com", subdomain="", tld="com", labels=["a", "com"],
            label_count=2, longest_label="a", longest_label_length=1, subdomain_length=0,
            timestamp=format_timestamp_standard(dt1), epoch_time=to_epoch_seconds(dt1),
            query_type="A", label=0, source="test"
        )
        r2 = NormalizedRecord(
            src_ip="10.0.0.1", dst_ip="8.8.8.8", requested_server_name="b.com",
            apex_domain="b.com", subdomain="", tld="com", labels=["b", "com"],
            label_count=2, longest_label="b", longest_label_length=1, subdomain_length=0,
            timestamp=format_timestamp_standard(dt2), epoch_time=to_epoch_seconds(dt2),
            query_type="A", label=0, source="test"
        )
        r3 = NormalizedRecord(
            src_ip="10.0.0.1", dst_ip="8.8.8.8", requested_server_name="c.com",
            apex_domain="c.com", subdomain="", tld="com", labels=["c", "com"],
            label_count=2, longest_label="c", longest_label_length=1, subdomain_length=0,
            timestamp=format_timestamp_standard(dt3), epoch_time=to_epoch_seconds(dt3),
            query_type="A", label=0, source="test"
        )

        unsorted_list = [r1, r3, r2]
        sorted_list = sort_records_chronologically(unsorted_list)
        self.assertEqual([r.requested_server_name for r in sorted_list], ["b.com", "a.com", "c.com"])


class TestValidationAndLeakageRules(unittest.TestCase):
    """Tests for validator.py and data leakage prevention."""

    def test_valid_record(self):
        rec = RawRecord(
            timestamp="2025-06-13 09:31:25.564",
            src_ip="10.0.30.186",
            dst_ip="8.8.8.8",
            requested_server_name="sub.example.com",
            label=0,
        )
        is_valid, err = validate_raw_record(rec)
        self.assertTrue(is_valid)
        self.assertIsNone(err)

    def test_missing_fields_fail(self):
        # Empty timestamp
        r1 = RawRecord("", "10.0.30.186", "8.8.8.8", "sub.example.com", 0)
        valid, err = validate_raw_record(r1)
        self.assertFalse(valid)
        self.assertIn("timestamp", err)

        # Empty IP
        r2 = RawRecord("2025-06-13 09:31:25.564", "", "8.8.8.8", "sub.example.com", 0)
        valid, err = validate_raw_record(r2)
        self.assertFalse(valid)
        self.assertIn("src_ip", err)

        # Invalid IP
        r3 = RawRecord("2025-06-13 09:31:25.564", "999.999.999.999", "8.8.8.8", "sub.example.com", 0)
        valid, err = validate_raw_record(r3)
        self.assertFalse(valid)
        self.assertIn("IP", err)

    def test_label_strictly_binary(self):
        rec_invalid_label = RawRecord(
            timestamp="2025-06-13 09:31:25.564",
            src_ip="10.0.30.186",
            dst_ip="8.8.8.8",
            requested_server_name="sub.example.com",
            label=2,  # Invalid
        )
        valid, err = validate_raw_record(rec_invalid_label)
        self.assertFalse(valid)
        self.assertIn("label", err.lower())

    def test_duplicate_record_handling(self):
        validator = DatasetValidator(check_duplicates=True)
        rec = RawRecord("2025-06-13 09:31:25.564", "10.0.30.186", "8.8.8.8", "sub.example.com", 0)
        
        valid1, _ = validator.process(rec)
        self.assertTrue(valid1)

        valid2, err2 = validator.process(rec)
        self.assertFalse(valid2)
        self.assertIn("Duplicate", err2)
        self.assertEqual(validator.report.duplicate_records, 1)

    def test_ml_feature_safety_enforcement(self):
        """CRITICAL: Test that raw identifiers and timestamps trigger DataLeakageError."""
        # Safe feature list (computed numerical properties)
        safe_features = [
            "dns_query_length",
            "dns_query_entropy",
            "dns_subdomain_count",
            "dns_numerical_ratio",
            "longest_label_length",
            "subdomain_length",
        ]
        # Should pass without raising
        verify_ml_feature_safety(safe_features)

        # Any disallowed raw feature should raise DataLeakageError
        for disallowed in DISALLOWED_RAW_ML_FEATURES:
            with self.subTest(disallowed=disallowed):
                leaky_features = safe_features + [disallowed]
                with self.assertRaises(DataLeakageError):
                    verify_ml_feature_safety(leaky_features)


class TestPipelineIntegration(unittest.TestCase):
    """End-to-end integration tests for PreprocessingPipeline."""

    def test_pipeline_row_mapping(self):
        pipeline = PreprocessingPipeline()
        sample_row = {
            "start_time": "2025-06-13 09:31:25.564",
            "source_ip": "10.0.30.186",
            "destination_ip": "8.8.8.8",
            "domain": "s.payload.data-relay.info.",
            "label": "1",
            "source": "CyberTrace Synthetic DNS Exfiltration v0.1",
        }
        raw = pipeline.parse_csv_row_to_raw_record(sample_row)
        self.assertEqual(raw.timestamp, "2025-06-13 09:31:25.564")
        self.assertEqual(raw.src_ip, "10.0.30.186")
        self.assertEqual(raw.dst_ip, "8.8.8.8")
        self.assertEqual(raw.requested_server_name, "s.payload.data-relay.info.")
        self.assertEqual(raw.label, 1)

        norm = pipeline.normalize_and_parse_record(raw)
        self.assertEqual(norm.requested_server_name, "s.payload.data-relay.info")
        self.assertEqual(norm.apex_domain, "data-relay.info")
        self.assertEqual(norm.subdomain, "s.payload")
        self.assertEqual(norm.label_count, 4)
        self.assertEqual(norm.longest_label, "data-relay")


if __name__ == "__main__":
    unittest.main()
