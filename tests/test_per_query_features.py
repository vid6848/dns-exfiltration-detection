import pytest
from src.preprocessing.schema import NormalizedRecord, verify_ml_feature_safety
from src.features.per_query import extract_per_query_features, calculate_entropy, FEATURE_NAMES

def get_dummy_record(**kwargs):
    default_args = {
        "src_ip": "10.0.0.1",
        "dst_ip": "8.8.8.8",
        "requested_server_name": "example.com",
        "apex_domain": "example.com",
        "subdomain": "",
        "tld": "com",
        "labels": ["example", "com"],
        "label_count": 2,
        "longest_label": "example",
        "longest_label_length": 7,
        "subdomain_length": 0,
        "timestamp": "2024-01-01 12:00:00.000",
        "epoch_time": 1704110400.0,
        "query_type": "A",
        "label": 0,
        "source": "test"
    }
    default_args.update(kwargs)
    return NormalizedRecord(**default_args)

def test_two_label_domain():
    record = get_dummy_record(
        requested_server_name="example.com",
        labels=["example", "com"],
        label_count=2
    )
    features = extract_per_query_features(record)
    assert features["number_of_labels"] == 2

def test_seven_label_domain():
    record = get_dummy_record(
        requested_server_name="a.b.c.d.e.example.com",
        labels=["a", "b", "c", "d", "e", "example", "com"],
        label_count=7
    )
    features = extract_per_query_features(record)
    assert features["number_of_labels"] == 7

def test_zero_digits():
    record = get_dummy_record(requested_server_name="example.com")
    features = extract_per_query_features(record)
    assert features["digit_ratio"] == 0.0

def test_digit_heavy_domain():
    name = "12345.example.com"
    record = get_dummy_record(requested_server_name=name)
    features = extract_per_query_features(record)
    assert features["digit_ratio"] > 0
    assert features["digit_ratio"] == 5 / len(name)

def test_pure_alphanumeric():
    # Only alphanumeric plus one dot (dot is non-alphanumeric).
    name = "example.com"
    record = get_dummy_record(requested_server_name=name)
    features = extract_per_query_features(record)
    # The dot should be the only non-alphanumeric character.
    assert features["special_char_ratio"] == 1 / len(name)

def test_special_characters():
    name = "my-test_domain.example.com"
    record = get_dummy_record(requested_server_name=name)
    features = extract_per_query_features(record)
    # '-' (1), '_' (1), '.' (2) = 4 special characters
    assert features["special_char_ratio"] == 4 / len(name)

def test_empty_input_safety():
    record = get_dummy_record(
        requested_server_name="",
        label_count=0,
        longest_label_length=0,
        subdomain_length=0
    )
    features = extract_per_query_features(record)
    assert features["query_length"] == 0
    assert features["entropy"] == 0.0
    assert features["digit_ratio"] == 0.0
    assert features["special_char_ratio"] == 0.0

def test_repeated_characters():
    # Mostly repeated characters vs varied characters
    varied = "abcdefgh.com"
    repeated = "aaaaaaah.com"
    ent_varied = calculate_entropy(varied)
    ent_repeated = calculate_entropy(repeated)
    assert ent_repeated < ent_varied

def test_structural_fields_from_preprocessing():
    record = get_dummy_record(
        longest_label_length=15,
        label_count=4,
        subdomain_length=8
    )
    features = extract_per_query_features(record)
    assert features["longest_label_length"] == 15
    assert features["number_of_labels"] == 4
    assert features["subdomain_length"] == 8

def test_feature_schema():
    record = get_dummy_record()
    features = extract_per_query_features(record)
    expected_keys = {
        "query_length",
        "longest_label_length",
        "number_of_labels",
        "entropy",
        "digit_ratio",
        "special_char_ratio",
        "subdomain_length"
    }
    assert set(features.keys()) == expected_keys

def test_data_leakage():
    # Ensure no raw fields are in the final dict
    record = get_dummy_record()
    features = extract_per_query_features(record)
    disallowed_keys = {
        "requested_server_name",
        "domain",
        "src_ip",
        "dst_ip",
        "timestamp",
        "source"
    }
    assert disallowed_keys.isdisjoint(features.keys())
    
    # Run the official safety check
    verify_ml_feature_safety(FEATURE_NAMES)
