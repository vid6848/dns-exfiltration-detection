"""Continuous DNS sensor that streams queries to the CyberTrace API.

Two sources feed the same POST /ingest stream:

  live    Sniff DNS queries (UDP/53) on a network interface with Scapy.
          Needs packet-capture privileges (sudo on macOS/Linux).
  replay  Re-play a labelled CSV as if it were live traffic, preserving the
          original gaps between queries. Used for demonstrations.

Every query is sent with one capture_id, so the API keeps a single sliding-window
history for this sensor across flushes. Suspicious results appear in GET /alerts
and therefore in the dashboard and the browser extension.

Examples:
    python -m scripts.dns_sensor replay data/demo/live_demo_stream.csv --api https://<host>
    sudo .venv/bin/python -m scripts.dns_sensor live --iface en0 --api http://127.0.0.1:8000
"""

import argparse
import csv
import json
import queue
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Dict, List


DOMAIN_COLUMNS = ("requested_server_name", "query", "domain")
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S.%f"
MAX_BATCH = 200


def format_timestamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime(TIMESTAMP_FORMAT)[:-3]


def post_batch(api: str, capture_id: str, queries: List[Dict[str, str]]) -> Dict:
    body = json.dumps({"capture_id": capture_id, "queries": queries}).encode("utf-8")
    request = urllib.request.Request(
        f"{api.rstrip('/')}/ingest",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def report(result: Dict) -> None:
    line = f"[ingest] accepted={result['accepted']} rejected={result['rejected']} suspicious={result['suspicious_queries']}"
    print(line, flush=True)
    for alert in result.get("alerts", []):
        print(
            f"  ALERT {alert['alert_id']}  {alert['risk_label']:<8} "
            f"score={alert['attack_score']:.3f}  {alert['src_ip']} -> {alert['requested_server_name']}",
            flush=True,
        )


class Uploader(threading.Thread):
    """Drains queued queries and posts them every flush interval or MAX_BATCH queries."""

    def __init__(self, api: str, capture_id: str, flush_seconds: float):
        super().__init__(daemon=True)
        self.api = api
        self.capture_id = capture_id
        self.flush_seconds = flush_seconds
        self.queue: "queue.Queue[Dict[str, str]]" = queue.Queue()
        self.stopping = threading.Event()

    def run(self) -> None:
        while not (self.stopping.is_set() and self.queue.empty()):
            batch = []
            deadline = time.monotonic() + self.flush_seconds
            while len(batch) < MAX_BATCH:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    batch.append(self.queue.get(timeout=remaining))
                except queue.Empty:
                    break
            if batch:
                self._send(batch)

    def _send(self, batch: List[Dict[str, str]]) -> None:
        try:
            report(post_batch(self.api, self.capture_id, batch))
        except urllib.error.HTTPError as exc:
            print(f"[ingest] HTTP {exc.code}: {exc.read().decode('utf-8', 'replace')[:300]}", file=sys.stderr)
        except (urllib.error.URLError, TimeoutError) as exc:
            print(f"[ingest] API unreachable ({exc}); dropped {len(batch)} queries", file=sys.stderr)

    def stop(self) -> None:
        self.stopping.set()
        self.join()


def run_replay(args: argparse.Namespace, uploader: Uploader) -> None:
    with open(args.csv, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        domain_column = next((c for c in DOMAIN_COLUMNS if c in (reader.fieldnames or [])), None)
        if domain_column is None:
            raise SystemExit(f"CSV needs one of these columns: {', '.join(DOMAIN_COLUMNS)}")
        rows = [row for row in reader if row.get(domain_column, "").strip()]

    timed = sorted(
        ((datetime.fromisoformat(row["timestamp"].strip()), row) for row in rows),
        key=lambda item: item[0],
    )
    origin = timed[0][0]
    replay_start = datetime.now(timezone.utc)
    previous_offset = 0.0
    print(f"[replay] {len(timed)} queries from {args.csv} at {args.speed}x speed", flush=True)

    for moment, row in timed:
        offset = (moment - origin).total_seconds()
        wait = (offset - previous_offset) / args.speed
        previous_offset = offset
        if wait > 0:
            time.sleep(min(wait, args.max_gap))
        uploader.queue.put({
            # Original gaps are kept in the event time so behavioral features stay faithful.
            "timestamp": format_timestamp(replay_start + timedelta(seconds=offset)),
            "src_ip": row.get("src_ip", "").strip() or "127.0.0.1",
            "dst_ip": row.get("dst_ip", "").strip() or "8.8.8.8",
            "requested_server_name": row[domain_column].strip(),
            "query_type": row.get("query_type", "").strip() or "A",
            "source": "CyberTrace replay sensor",
        })


def run_live(args: argparse.Namespace, uploader: Uploader) -> None:
    try:
        from scapy.all import DNS, DNSQR, IP, IPv6, sniff  # noqa: WPS433 (optional dependency)
    except ImportError as exc:
        raise SystemExit("Live capture needs scapy: pip install -r requirements-data.txt") from exc

    def handle(packet):
        if not packet.haslayer(DNSQR) or packet[DNS].qr != 0:
            return
        network = packet[IP] if packet.haslayer(IP) else packet[IPv6] if packet.haslayer(IPv6) else None
        if network is None:
            return
        name = packet[DNSQR].qname.decode("utf-8", "replace").rstrip(".")
        if not name:
            return
        qtype = packet[DNSQR].get_field("qtype").i2repr(packet[DNSQR], packet[DNSQR].qtype)
        uploader.queue.put({
            "timestamp": format_timestamp(datetime.fromtimestamp(float(packet.time), timezone.utc)),
            "src_ip": network.src,
            "dst_ip": network.dst,
            "requested_server_name": name,
            "query_type": str(qtype),
            "source": "CyberTrace live sensor",
        })
        if args.verbose:
            print(f"  dns {network.src} -> {name}", flush=True)

    print(f"[live] sniffing DNS queries on {args.iface or 'default interface'} (Ctrl+C to stop)", flush=True)
    sniff(iface=args.iface, filter="udp port 53", prn=handle, store=False)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--api", default="http://127.0.0.1:8000", help="CyberTrace API base URL")
    parser.add_argument("--capture-id", default=f"sensor-{socket.gethostname()}", help="behavioral history key")
    parser.add_argument("--flush", type=float, default=2.0, help="seconds between uploads")
    modes = parser.add_subparsers(dest="mode", required=True)

    replay = modes.add_parser("replay", help="replay a CSV as live traffic")
    replay.add_argument("csv")
    replay.add_argument("--speed", type=float, default=1.0, help="playback speed multiplier")
    replay.add_argument("--max-gap", type=float, default=3.0, help="cap any single wall-clock wait (seconds)")

    live = modes.add_parser("live", help="sniff DNS on a network interface")
    live.add_argument("--iface", default=None)
    live.add_argument("--verbose", action="store_true")

    args = parser.parse_args()
    uploader = Uploader(args.api, args.capture_id, args.flush)
    uploader.start()
    try:
        if args.mode == "replay":
            run_replay(args, uploader)
        else:
            run_live(args, uploader)
    except KeyboardInterrupt:
        pass
    finally:
        uploader.stop()


if __name__ == "__main__":
    main()
