"""
fleet_reporting.py

Optional capability: ships every finding from this machine to a central
collector over HTTP, so multiple RAM-Guard-protected machines can be
watched from one place instead of each being its own island (a local log,
local dashboard, local report per machine, with no combined view).

Disabled by default. When enabled, every finding from all four detection
layers is POSTed to `collector_url`, regardless of severity or --silent
mode -- --silent only suppresses local desktop/mobile/email interruptions
on THIS machine; central reporting is the mechanism a fleet deployment
would rely on instead of that, so it isn't silenced by the same flag.

Honest scope: this file (the sender) and fleet_collector_example.py (a
reference receiver) have been tested against each other end-to-end on one
machine -- confirmed the wire format, the HTTP contract, and the API-key
check all work correctly. That is real validation of the protocol. It is
NOT validation of a real multi-device fleet, which would need actual
different machines reporting in; that still doesn't exist here. Don't
present this as "fleet-tested" -- present it as "the mechanism works,
proven against a real receiver, not yet proven across real hardware
diversity."

Security note, stated plainly rather than glossed over: this ships
security findings over plain HTTP with an optional shared API key -- no
TLS, no per-device credentials. That's adequate for a local/trusted
network demo, not for anything resembling a production deployment on a
real network. See the README's Fleet Reporting section for what a
production version would need.
"""

import logging
import socket
import time
from datetime import datetime, timezone

import requests

logger = logging.getLogger("ram_guard.fleet")


class FleetReporter:
    def __init__(self, enabled: bool = False, collector_url: str = "",
                 device_id: str = "", api_key: str = "", timeout: float = 5.0):
        self.enabled = enabled and bool(collector_url)
        self.collector_url = collector_url.rstrip("/")
        self.device_id = device_id or socket.gethostname()
        self.api_key = api_key
        self.timeout = timeout

    def report(self, layer: str, fields: dict):
        """Best-effort: never raises, never blocks the caller on a slow/dead
        collector for longer than `timeout`. A fleet collector being
        unreachable should not stop local monitoring from working."""
        if not self.enabled:
            return
        payload = {
            "device_id": self.device_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "layer": layer,
            **fields,
        }
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        try:
            requests.post(f"{self.collector_url}/report", json=payload,
                          headers=headers, timeout=self.timeout)
        except requests.RequestException as e:
            logger.warning("Fleet report failed (collector unreachable?): %s", e)
