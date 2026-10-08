"""
Domain Label Parsing and Decomposition Module
Project: DNS Exfiltration Detection Using Network Traffic Analysis (CE305/CS305)

Owner: Yash (Preprocessing and Parsing)

Provides:
- Dot-separated label tokenization.
- Top-Level Domain (TLD) identification.
- Registered/Apex Domain (eTLD+1) extraction for grouping behavioral windows (Rudraksh).
- Subdomain isolation and character length metrics (Hero).
- Longest label extraction and count.
"""

from dataclasses import dataclass
from typing import List, Set


# Common multi-part public suffixes and internal cloud suffixes found in network datasets
KNOWN_MULTI_PART_SUFFIXES: Set[str] = {
    # Special Infrastructure / Reverse DNS
    "in-addr.arpa",
    "ip6.arpa",
    # Cloud internal endpoints (common in cloud VPC captures like Mendeley)
    "compute.internal",
    "sa-east-1.compute.internal",
    "us-east-1.compute.internal",
    "us-west-2.compute.internal",
    "ec2.internal",
    # Second-level country code TLDs
    "co.uk", "org.uk", "gov.uk", "ac.uk",
    "co.in", "net.in", "org.in", "gov.in", "ac.in",
    "com.au", "net.au", "org.au", "edu.au",
    "co.jp", "ne.jp", "ac.jp",
    "com.br", "org.br", "net.br",
    "com.cn", "net.cn", "org.cn",
    "co.nz", "net.nz", "org.nz",
    "com.sg", "edu.sg",
}


@dataclass
class DomainComponents:
    """Decomposed structural components of a normalized DNS domain."""
    labels: List[str]
    label_count: int
    longest_label: str
    longest_label_length: int
    tld: str
    apex_domain: str
    subdomain: str
    subdomain_labels: List[str]
    subdomain_length: int


def parse_domain_labels(normalized_domain: str) -> DomainComponents:
    """
    Decomposes a normalized domain into structured components.

    Example:
        's.wphamt5t5bjr6k2pwa32h2u4.data-relay.info'
        -> labels: ['s', 'wphamt5t5bjr6k2pwa32h2u4', 'data-relay', 'info']
        -> label_count: 4
        -> longest_label: 'wphamt5t5bjr6k2pwa32h2u4' (length 24)
        -> tld: 'info'
        -> apex_domain: 'data-relay.info'
        -> subdomain: 's.wphamt5t5bjr6k2pwa32h2u4'
        -> subdomain_labels: ['s', 'wphamt5t5bjr6k2pwa32h2u4']
        -> subdomain_length: 26

    Handles:
        - Multi-part suffixes (e.g. '.co.uk', '.in-addr.arpa', '.compute.internal')
        - Standard two-part domains (e.g. 'example.com')
        - Deep nested subdomains (e.g. 'a.b.c.d.example.com')
    """
    if not normalized_domain:
        return DomainComponents(
            labels=[],
            label_count=0,
            longest_label="",
            longest_label_length=0,
            tld="",
            apex_domain="",
            subdomain="",
            subdomain_labels=[],
            subdomain_length=0,
        )

    labels = normalized_domain.split(".")
    label_count = len(labels)
    longest_label = max(labels, key=len) if labels else ""
    longest_label_length = len(longest_label)

    # 1. Check for multi-part suffix matches from longest to shortest
    matched_suffix = None
    suffix_label_count = 1

    # Check 3-part suffix (e.g. sa-east-1.compute.internal)
    if label_count >= 4:
        three_part = ".".join(labels[-3:])
        if three_part in KNOWN_MULTI_PART_SUFFIXES:
            matched_suffix = three_part
            suffix_label_count = 3

    # Check 2-part suffix (e.g. co.uk, in-addr.arpa, compute.internal)
    if not matched_suffix and label_count >= 3:
        two_part = ".".join(labels[-2:])
        if two_part in KNOWN_MULTI_PART_SUFFIXES:
            matched_suffix = two_part
            suffix_label_count = 2

    if matched_suffix:
        tld = matched_suffix
        # Apex domain includes 1 label before suffix (e.g., domain.co.uk)
        apex_labels_count = suffix_label_count + 1
        if label_count >= apex_labels_count:
            apex_domain = ".".join(labels[-apex_labels_count:])
            subdomain_labels = labels[:-apex_labels_count]
        else:
            apex_domain = normalized_domain
            subdomain_labels = []
    else:
        # Standard 1-part TLD (e.g. 'com', 'org', 'io')
        tld = labels[-1]
        if label_count >= 2:
            apex_domain = ".".join(labels[-2:])
            subdomain_labels = labels[:-2]
        else:
            apex_domain = normalized_domain
            subdomain_labels = []

    subdomain = ".".join(subdomain_labels)
    subdomain_length = len(subdomain)

    return DomainComponents(
        labels=labels,
        label_count=label_count,
        longest_label=longest_label,
        longest_label_length=longest_label_length,
        tld=tld,
        apex_domain=apex_domain,
        subdomain=subdomain,
        subdomain_labels=subdomain_labels,
        subdomain_length=subdomain_length,
    )
