import math
from typing import Dict, Any, Union
from src.preprocessing.schema import NormalizedRecord

FEATURE_NAMES = [
    "query_length",
    "longest_label_length",
    "number_of_labels",
    "entropy",
    "digit_ratio",
    "special_char_ratio",
    "subdomain_length",
]

def calculate_entropy(value: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not value:
        return 0.0
    
    length = len(value)
    counts = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
        
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
        
    return entropy

def extract_per_query_features(record: NormalizedRecord) -> Dict[str, Union[int, float]]:
    """
    Extracts numerical per-query DNS features from a normalized record.
    """
    server_name = record.requested_server_name
    query_length = len(server_name)
    
    if query_length > 0:
        digits = sum(1 for c in server_name if c in "0123456789")
        digit_ratio = digits / query_length
        
        # non-alphanumeric characters, defined as not isalnum(). Note that '.' is not isalnum() so it is counted.
        # The prompt says: "Use the project's stated definition: non-alphanumeric characters. Examples include: -, _. The implementation should use a clear deterministic definition, such as Python's character classification: not character.isalnum(). Document this behavior."
        special_chars = sum(1 for c in server_name if not c.isalnum())
        special_char_ratio = special_chars / query_length
    else:
        digit_ratio = 0.0
        special_char_ratio = 0.0
        
    entropy = calculate_entropy(server_name)
    
    features = {
        "query_length": query_length,
        "longest_label_length": record.longest_label_length,
        "number_of_labels": record.label_count,
        "entropy": float(entropy),
        "digit_ratio": float(digit_ratio),
        "special_char_ratio": float(special_char_ratio),
        "subdomain_length": record.subdomain_length,
    }
    
    return features
