#!/usr/bin/env python3
"""
Synthetic DNS Exfiltration Dataset Generator
Project: DNS Exfiltration Detection Using Network Traffic Analysis (CyberTrace)

Generates controlled, varied, synthetic DNS-exfiltration-like network records
adhering strictly to the 10-column schema established in benign_dns_v0.1.csv.

Profiles supported:
  A. Encoded-looking chunked subdomains (Base64/alphanumeric multi-label chunks)
  B. Hexadecimal-like payload chunks (dnscat2 / hex tunnel emulation)
  C. Base32-like payload chunks (RFC 4648 Base32 uppercase/lowercase emulation)
  D. Variable-length payload chunks (short to medium payload emulation)
  E. Low-and-slow DNS activity (covert drip exfiltration with wide time deltas)
  F. High-frequency / burst DNS activity (automated bulk exfiltration bursts)
  G. Multiple subdomain structures (variable label depths: 3 to 7 labels)

All records use label = 1.
"""

import argparse
from collections import Counter
import csv
from datetime import datetime, timedelta
import math
from pathlib import Path
import random
import string
import sys
from typing import Dict, List, Optional, Tuple

EXPECTED_COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "requested_server_name",
    "dns_query_length",
    "dns_query_entropy",
    "dns_subdomain_count",
    "dns_numerical_ratio",
    "label",
    "source",
]

DEFAULT_SOURCE_TAG = "CyberTrace Synthetic DNS Exfiltration v0.1"

# Default realistic base domains across diverse TLDs
DEFAULT_BASE_DOMAINS = [
    "exfil-corp.org",
    "tunnel-sync.net",
    "ns-update-check.com",
    "cloud-telemetry.io",
    "data-relay.info",
    "system-metrics.biz",
    "sec-agent-update.xyz",
    "internal-monitor.cc",
    "srv-heartbeat.co",
    "edge-cdn-beacon.live",
]

# Default private client IPs (includes benign dominant IP 10.0.30.186 to prevent IP-based shortcut learning)
DEFAULT_SRC_IPS = [
    "10.0.30.186",  # 50% weighted by default to emulate compromised primary benign host
    "10.0.30.164",  # Secondary testbed host
    "10.0.30.100",  # Workstation 1
    "10.0.30.230",  # Workstation 2
    "192.168.1.105",  # Subnet B host
    "172.16.10.42",  # Subnet C host
]

# Default DNS resolvers
DEFAULT_DST_IPS = [
    "8.8.8.8",  # Google Public DNS (dominant in benign dataset)
    "1.1.1.1",  # Cloudflare Public DNS
    "9.9.9.9",  # Quad9 Public DNS
    "10.0.0.2",  # Internal / gateway resolver
]

BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"
HEX_ALPHABET = "0123456789abcdef"
B64_LIKE_ALPHABET = string.ascii_lowercase + string.ascii_uppercase + string.digits + "-_"


def compute_shannon_entropy(s: str) -> float:
    """Computes Shannon entropy (base 2) over the full string."""
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((cnt / total) * math.log2(cnt / total) for cnt in counts.values())


def compute_features(fqdn: str) -> Tuple[int, float, int, float]:
    """
    Computes exact DNS features as defined in benign_dns_v0.1.csv:
      - dns_query_length: exact length of requested_server_name
      - dns_query_entropy: Shannon entropy (base 2) of complete string
      - dns_subdomain_count: number of dot-separated labels
      - dns_numerical_ratio: count of digits / total length
    """
    length = len(fqdn)
    entropy = compute_shannon_entropy(fqdn)
    subdomain_count = len(fqdn.split("."))
    num_digits = sum(c.isdigit() for c in fqdn)
    numerical_ratio = (num_digits / length) if length > 0 else 0.0
    return length, entropy, subdomain_count, numerical_ratio


def generate_payload_chunk(
    rng: random.Random,
    encoding_type: str,
    length: int,
) -> str:
    """Generates synthetic payload string of specified encoding and length."""
    if encoding_type == "hex":
        return "".join(rng.choice(HEX_ALPHABET) for _ in range(length))
    elif encoding_type == "base32":
        return "".join(rng.choice(BASE32_ALPHABET) for _ in range(length))
    elif encoding_type == "b64_like":
        # DNS labels are case-insensitive in practice, but base64-like subdomains
        # often use lower/upper mixed or url-safe chars
        # We lowercase to adhere to standard DNS resolution behavior
        chars = string.ascii_lowercase + string.digits
        return "".join(rng.choice(chars) for _ in range(length))
    elif encoding_type == "alphanumeric_mixed":
        chars = string.ascii_lowercase + string.digits
        return "".join(rng.choice(chars) for _ in range(length))
    else:
        return "".join(rng.choice(HEX_ALPHABET) for _ in range(length))


class AttackCampaign:
    """Represents a coherent exfiltration session or campaign over time."""

    def __init__(
        self,
        campaign_id: str,
        profile_type: str,
        base_domain: str,
        src_ip: str,
        dst_ip: str,
        timing_mode: str,
        start_time: datetime,
        rng: random.Random,
    ):
        self.campaign_id = campaign_id
        self.profile_type = profile_type
        self.base_domain = base_domain
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.timing_mode = timing_mode  # 'burst' or 'low_and_slow'
        self.current_time = start_time
        self.rng = rng
        self.seq_num = 0
        self.session_token = "".join(rng.choice(HEX_ALPHABET) for _ in range(6))

    def next_query(self) -> Tuple[str, datetime, str]:
        """Generates the next FQDN and timestamp for this campaign."""
        self.seq_num += 1
        seq_str = f"{self.seq_num:04x}"

        # Determine structural pattern and encoding based on profile_type
        if self.profile_type == "profile_a_chunked_b64":
            # Encoded-looking chunked subdomains: e.g. <chunk1>.<chunk2>.<session>.<domain>
            chunk1 = generate_payload_chunk(self.rng, "b64_like", self.rng.randint(8, 18))
            chunk2 = generate_payload_chunk(self.rng, "b64_like", self.rng.randint(8, 18))
            fqdn = f"{chunk1}.{chunk2}.{self.session_token}.{self.base_domain}"

        elif self.profile_type == "profile_b_hex":
            # Hexadecimal-like payload chunks (dnscat2 style): e.g. dnscat.<hex_payload>.<domain>
            # Or <seq>.<hex_payload>.<domain>
            prefix = self.rng.choice(["dnscat", "d", "c2", "x", seq_str])
            payload_len = self.rng.choice([16, 24, 32, 40])
            hex_chunk = generate_payload_chunk(self.rng, "hex", payload_len)
            if self.rng.random() < 0.5:
                fqdn = f"{prefix}.{hex_chunk}.{self.base_domain}"
            else:
                chunk2 = generate_payload_chunk(self.rng, "hex", self.rng.randint(8, 16))
                fqdn = f"{prefix}.{hex_chunk}.{chunk2}.{self.base_domain}"

        elif self.profile_type == "profile_c_base32":
            # Base32-like payload chunks (RFC 4648 lowercase): e.g. <seq>.<b32_data>.<domain>
            b32_len = self.rng.choice([16, 24, 32, 40])
            b32_chunk = generate_payload_chunk(self.rng, "base32", b32_len)
            sub_id = self.rng.choice(["s", "q", "id", seq_str])
            fqdn = f"{sub_id}.{b32_chunk}.{self.base_domain}"

        elif self.profile_type == "profile_d_variable_length":
            # Variable-length payloads (short credentials/tokens to moderate files)
            # Intentionally includes shorter payloads to create overlap with benign query lengths
            length = self.rng.randint(6, 48)
            enc = self.rng.choice(["hex", "base32", "b64_like"])
            chunk = generate_payload_chunk(self.rng, enc, length)
            fqdn = f"{chunk}.{self.base_domain}"

        elif self.profile_type == "profile_g_multi_structure":
            # Variable label depths: 4 to 7 labels total
            depth = self.rng.choice([4, 5, 6, 7])
            labels = []
            labels.append(seq_str)
            base_label_count = len(self.base_domain.split("."))  # usually 2
            subdomain_labels_needed = depth - base_label_count - 1
            for _ in range(max(1, subdomain_labels_needed)):
                l_len = self.rng.randint(4, 14)
                enc = self.rng.choice(["hex", "base32", "b64_like"])
                labels.append(generate_payload_chunk(self.rng, enc, l_len))
            labels.append(self.session_token)
            fqdn = ".".join(labels) + "." + self.base_domain

        else:
            # Fallback balanced exfiltration
            chunk = generate_payload_chunk(self.rng, "b64_like", self.rng.randint(12, 30))
            fqdn = f"{chunk}.{self.base_domain}"

        # Check RFC length bounds (max label length 63, max total length 253)
        parts = fqdn.split(".")
        adjusted_parts = [p[:63] if len(p) > 63 else p for p in parts]
        fqdn = ".".join(adjusted_parts)
        if len(fqdn) > 253:
            fqdn = fqdn[:253].rstrip(".")

        timestamp_val = self.current_time

        # Advance timestamp based on timing mode
        if self.timing_mode == "burst":
            # High-frequency: 0.05s to 1.5s delta
            delta_ms = self.rng.uniform(50.0, 1500.0)
            self.current_time += timedelta(milliseconds=delta_ms)
        else:
            # Low-and-slow: 15s to 300s delta
            delta_sec = self.rng.uniform(15.0, 300.0)
            self.current_time += timedelta(seconds=delta_sec)

        return fqdn, timestamp_val, self.profile_type


def generate_synthetic_dataset(
    num_records: int,
    seed: int = 42,
    start_time_str: str = "2025-06-13 09:31:25.666",
    end_time_str: str = "2025-06-14 09:01:06.636",
    base_domains: Optional[List[str]] = None,
    src_ips: Optional[List[str]] = None,
    dst_ips: Optional[List[str]] = None,
    source_tag: str = DEFAULT_SOURCE_TAG,
) -> Tuple[List[Dict[str, str]], Dict[str, any]]:
    """Generates synthetic DNS exfiltration records."""
    rng = random.Random(seed)

    domains = base_domains if base_domains else DEFAULT_BASE_DOMAINS
    sources = src_ips if src_ips else DEFAULT_SRC_IPS
    resolvers = dst_ips if dst_ips else DEFAULT_DST_IPS

    start_dt = datetime.strptime(start_time_str, "%Y-%m-%d %H:%M:%S.%f")
    end_dt = datetime.strptime(end_time_str, "%Y-%m-%d %H:%M:%S.%f")
    total_window_seconds = (end_dt - start_dt).total_seconds()

    # Profiles to instantiate
    structural_profiles = [
        "profile_a_chunked_b64",
        "profile_b_hex",
        "profile_c_base32",
        "profile_d_variable_length",
        "profile_g_multi_structure",
    ]

    # Pre-create several active campaigns distributed across the time window
    # Aim for a mix of burst and low-and-slow campaigns
    num_campaigns = max(10, num_records // 50)
    campaigns: List[AttackCampaign] = []

    for i in range(num_campaigns):
        p_type = rng.choice(structural_profiles)
        b_dom = rng.choice(domains)

        # Source IP weighting: 50% chance of 10.0.30.186 (benign dominant IP), 50% other private IPs
        if rng.random() < 0.50:
            c_src = "10.0.30.186"
        else:
            c_src = rng.choice([ip for ip in sources if ip != "10.0.30.186"] or sources)

        c_dst = rng.choice(resolvers)
        t_mode = rng.choice(["burst", "low_and_slow"])

        # Offset start time randomly within first 85% of window so campaigns finish before end_dt
        offset_sec = rng.uniform(0.0, total_window_seconds * 0.85)
        c_start = start_dt + timedelta(seconds=offset_sec)

        camp = AttackCampaign(
            campaign_id=f"camp_{i:04d}",
            profile_type=p_type,
            base_domain=b_dom,
            src_ip=c_src,
            dst_ip=c_dst,
            timing_mode=t_mode,
            start_time=c_start,
            rng=random.Random(rng.randint(0, 1000000)),
        )
        campaigns.append(camp)

    records: List[Dict[str, any]] = []
    seen_fqdns = set()
    profile_counter = Counter()

    # Generate records round-robin across campaigns
    campaign_idx = 0
    while len(records) < num_records:
        camp = campaigns[campaign_idx % len(campaigns)]
        campaign_idx += 1

        # If campaign passed end_dt, re-seed its time earlier in window
        if camp.current_time >= end_dt:
            camp.current_time = start_dt + timedelta(seconds=rng.uniform(0.0, total_window_seconds * 0.70))

        fqdn, query_time, prof = camp.next_query()

        # Deduplication check: if collision, append a small random nonce label
        if fqdn in seen_fqdns:
            nonce = generate_payload_chunk(rng, "hex", 4)
            parts = fqdn.split(".", 1)
            fqdn = f"{parts[0]}-{nonce}.{parts[1]}"
        seen_fqdns.add(fqdn)

        length, entropy, subdomain_count, numerical_ratio = compute_features(fqdn)

        # Format timestamp to 3 decimal places (milliseconds)
        ts_formatted = query_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        record = {
            "timestamp": ts_formatted,
            "src_ip": camp.src_ip,
            "dst_ip": camp.dst_ip,
            "requested_server_name": fqdn,
            "dns_query_length": length,
            "dns_query_entropy": entropy,
            "dns_subdomain_count": subdomain_count,
            "dns_numerical_ratio": numerical_ratio,
            "label": 1,
            "source": source_tag,
            "_profile": prof,
            "_timing": camp.timing_mode,
        }
        records.append(record)
        profile_counter[prof] += 1
        profile_counter[f"timing_{camp.timing_mode}"] += 1

    # Sort records chronologically to emulate realistic captured traffic stream
    records.sort(key=lambda r: r["timestamp"])

    metadata = {
        "num_records": len(records),
        "seed": seed,
        "profiles": dict(profile_counter),
        "start_time": start_time_str,
        "end_time": end_time_str,
        "base_domains": domains,
        "src_ips": sources,
        "dst_ips": resolvers,
    }

    return records, metadata


def write_dataset_to_csv(records: List[Dict[str, any]], output_path: Path) -> None:
    """Writes generated records to CSV using exactly the EXPECTED_COLUMNS."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=EXPECTED_COLUMNS)
        writer.writeheader()
        for r in records:
            # Filter internal debug metadata keys starting with '_'
            row_dict = {col: r[col] for col in EXPECTED_COLUMNS}
            writer.writerow(row_dict)


def main():
    parser = argparse.ArgumentParser(
        description="Generate synthetic DNS exfiltration dataset adhering to benign_dns_v0.1.csv schema."
    )
    parser.add_argument(
        "--num-records",
        type=int,
        default=10000,
        help="Number of synthetic records to generate (default: 10000)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Deterministic random seed for reproducibility (default: 42)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/processed/synthetic_exfiltration_v0.1.csv",
        help="Output CSV path (default: data/processed/synthetic_exfiltration_v0.1.csv)",
    )
    parser.add_argument(
        "--source-tag",
        type=str,
        default=DEFAULT_SOURCE_TAG,
        help=f"Dataset provenance source string (default: '{DEFAULT_SOURCE_TAG}')",
    )
    parser.add_argument(
        "--start-time",
        type=str,
        default="2025-06-13 09:31:25.666",
        help="Earliest timestamp bound (default: 2025-06-13 09:31:25.666)",
    )
    parser.add_argument(
        "--end-time",
        type=str,
        default="2025-06-14 09:01:06.636",
        help="Latest timestamp bound (default: 2025-06-14 09:01:06.636)",
    )
    parser.add_argument(
        "--base-domains",
        type=str,
        default=None,
        help="Comma-separated list of synthetic base domains",
    )
    parser.add_argument(
        "--src-ips",
        type=str,
        default=None,
        help="Comma-separated list of client source IPs",
    )
    parser.add_argument(
        "--dst-ips",
        type=str,
        default=None,
        help="Comma-separated list of destination resolver IPs",
    )

    args = parser.parse_args()

    custom_domains = [d.strip() for d in args.base_domains.split(",")] if args.base_domains else None
    custom_srcs = [ip.strip() for ip in args.src_ips.split(",")] if args.src_ips else None
    custom_dsts = [ip.strip() for ip in args.dst_ips.split(",")] if args.dst_ips else None

    print(f"Generating {args.num_records:,} synthetic attack records (Seed: {args.seed})...")
    records, meta = generate_synthetic_dataset(
        num_records=args.num_records,
        seed=args.seed,
        start_time_str=args.start_time,
        end_time_str=args.end_time,
        base_domains=custom_domains,
        src_ips=custom_srcs,
        dst_ips=custom_dsts,
        source_tag=args.source_tag,
    )

    out_path = Path(args.output)
    write_dataset_to_csv(records, out_path)
    print(f"Dataset successfully written to: {out_path}")
    print(f"Summary Profiles: {meta['profiles']}")


if __name__ == "__main__":
    main()
