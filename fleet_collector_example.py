"""
fleet_collector_example.py

A REFERENCE central collector for fleet_reporting.py -- receives findings
posted by one or more RAM-Guard instances and stores them in one place,
so multiple machines can be reviewed from a single point instead of each
being its own island.

This is a minimal, honest reference implementation, not a production
collector: stdlib-only HTTP server, findings appended to a local JSONL
file, an optional shared API key for a basic layer of protection. No TLS,
no per-device credentials, no database. A production version behind a
real network would need at minimum: HTTPS, per-device auth tokens (not
one shared key), and a real datastore instead of a flat file -- stated
here rather than glossed over.

Usage:
    python fleet_collector_example.py                    # port 9000, no auth
    python fleet_collector_example.py --port 9000 --api-key mysecret
    python fleet_collector_example.py --summary           # print aggregated view and exit
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

STORE_PATH = Path(__file__).parent / "fleet_findings.jsonl"

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def make_handler(api_key: str):
    class CollectorHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass  # quiet -- we print our own structured lines below

        def do_POST(self):
            if self.path != "/report":
                self.send_response(404)
                self.end_headers()
                return

            if api_key and self.headers.get("X-API-Key") != api_key:
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b'{"error": "invalid or missing API key"}')
                return

            length = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(length))
            except (ValueError, json.JSONDecodeError):
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error": "invalid JSON"}')
                return

            body["_received_at"] = datetime.now().isoformat()
            body["_remote_addr"] = self.client_address[0]
            with open(STORE_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(body) + "\n")

            print(f"[{body['_received_at']}] received from device={body.get('device_id')} "
                  f"layer={body.get('layer')} kind={body.get('kind', body.get('category', '?'))} "
                  f"severity={body.get('severity', '?')}")

            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}')

    return CollectorHandler


def print_summary():
    if not STORE_PATH.exists():
        print("No findings received yet.")
        return
    rows = [json.loads(line) for line in STORE_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]
    by_device = Counter(r.get("device_id", "unknown") for r in rows)
    by_device_layer = defaultdict(Counter)
    for r in rows:
        by_device_layer[r.get("device_id", "unknown")][r.get("layer", "unknown")] += 1

    print("=" * 60)
    print(f"FLEET SUMMARY -- {len(rows)} findings from {len(by_device)} device(s)")
    print("=" * 60)
    for device, count in by_device.most_common():
        print(f"\n{device}: {count} findings")
        for layer, n in by_device_layer[device].most_common():
            print(f"    {layer:12s} {n}")


def main():
    parser = argparse.ArgumentParser(description="Reference fleet collector for RAM-Guard")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--api-key", default="", help="If set, reject requests without a matching X-API-Key header")
    parser.add_argument("--summary", action="store_true", help="Print aggregated findings and exit, no server")
    args = parser.parse_args()

    if args.summary:
        print_summary()
        return

    server = ThreadingHTTPServer(("0.0.0.0", args.port), make_handler(args.api_key))
    print(f"Fleet collector listening on http://0.0.0.0:{args.port} "
          f"(API key {'required' if args.api_key else 'not required'})")
    print(f"Findings stored in {STORE_PATH}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
