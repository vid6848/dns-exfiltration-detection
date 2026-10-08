"""
Domain Normalization Module
Project: DNS Exfiltration Detection Using Network Traffic Analysis (CE305/CS305)

Owner: Yash (Preprocessing and Parsing)

Handles:
- Case-folding to lowercase (RFC 1035 standard: DNS is case-insensitive).
- Stripping root trailing dot (FQDN format e.g. 'example.com.' -> 'example.com').
- Stripping extraneous whitespace, quotation marks, accidental schemes (http://, https://).
- Stripping accidental path or port specifications.
- Validating RFC 1035 / RFC 1123 domain syntax (label <= 63 chars, total <= 253 chars).
"""

import re
from typing import Tuple


# Regex to detect and strip scheme/URL components if present
SCHEME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
PORT_PATTERN = re.compile(r":\d+$")

# RFC 1035 / 1123 label pattern: letters, numbers, hyphens (and underscores in internal infrastructure)
LABEL_PATTERN = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")


def normalize_domain(domain_str: str) -> str:
    """
    Normalizes a DNS query or domain name string deterministically.

    Steps:
    1. Strip leading and trailing whitespace and quotes.
    2. Remove accidental URL scheme prefixes (e.g., 'http://', 'https://').
    3. Remove path, query string, or fragment suffixes (e.g., '/path?query').
    4. Remove trailing port specification (e.g., ':53', ':80').
    5. Case-fold to lowercase (DNS case-insensitivity).
    6. Strip trailing dot (DNS root notation, e.g., 'example.com.' -> 'example.com').

    Returns:
        The normalized domain string.
    """
    if domain_str is None:
        return ""

    s = str(domain_str).strip().strip("\"'").strip()
    if not s:
        return ""

    # Strip scheme if present (e.g. 'https://sub.example.com' -> 'sub.example.com')
    s = SCHEME_PATTERN.sub("", s)

    # Strip path or query if present (e.g. 'sub.example.com/login?foo=1' -> 'sub.example.com')
    for delimiter in ("/", "?", "#"):
        if delimiter in s:
            s = s.split(delimiter, 1)[0]

    # Strip port if present (e.g. 'sub.example.com:53' -> 'sub.example.com')
    s = PORT_PATTERN.sub("", s)

    # Case-fold to lowercase
    s = s.lower().strip()

    # Strip trailing dot (FQDN root terminator)
    while s.endswith("."):
        s = s[:-1]

    # Strip leading dot if accidentally present
    while s.startswith("."):
        s = s[1:]

    return s


def is_valid_fqdn(domain: str) -> Tuple[bool, str]:
    """
    Validates a domain string against RFC 1035 / RFC 1123 constraints.

    Rules:
    - Non-empty.
    - Total character length must be between 1 and 253 characters.
    - Must contain at least two labels separated by a dot (e.g., 'example.com' or 'localhost.localdomain').
    - Each label must be between 1 and 63 characters in length.
    - Labels must contain only alphanumeric characters, hyphens, and underscores (for internal DNS like AWS/reverse arpa).
    - Labels must not start or end with a hyphen.
    - No empty labels (e.g., '..').

    Returns:
        (is_valid, error_reason)
    """
    if not domain:
        return False, "Domain is empty or null."

    if len(domain) > 253:
        return False, f"Domain exceeds maximum total length of 253 characters (got {len(domain)})."

    labels = domain.split(".")
    if len(labels) < 2:
        return False, f"Domain must contain at least 2 dot-separated labels (got {len(labels)}: '{domain}')."

    for i, label in enumerate(labels):
        if len(label) == 0:
            return False, f"Empty label detected at position {i} (consecutive dots)."
        if len(label) > 63:
            return False, f"Label '{label[:15]}...' exceeds maximum 63 characters (got {len(label)})."
        if label.startswith("-") or label.endswith("-"):
            return False, f"Label '{label}' cannot begin or end with a hyphen."
        if not LABEL_PATTERN.match(label):
            return False, f"Label '{label}' contains invalid characters."

    return True, ""
