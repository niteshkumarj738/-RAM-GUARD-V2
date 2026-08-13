"""
generate_security_console.py

Generates a standalone, self-contained HTML "Device Security Console" from
real RAM-Guard data: findings parsed from ram_guard.log, plus a live system
snapshot (RAM, uptime) via psutil. No server needed -- open the generated
HTML file directly in any browser.

Shows one device: this machine. RAM-Guard does not do multi-device/fleet
monitoring, so the console intentionally reflects that rather than
fabricating other devices.

This is a report generator, same pattern as
test_scenarios/summarize_baseline.py -- re-run it any time for a fresh
snapshot; it does not run the live monitor itself.

Usage:
    python generate_security_console.py
    python generate_security_console.py --log ram_guard.log --out security_console.html
"""

import argparse
import json
import re
import socket
from datetime import datetime
from pathlib import Path

import psutil

LINE_RE = re.compile(
    r"^(?P<ts>[\d\-]+ [\d:,]+) \| \w+\s+\| ram_guard\.\w+ \| "
    r"(?:Process|Crash) finding: pid=(?P<pid>\d+) name=(?P<name>\S+) kind=(?P<kind>\S+) "
    r"severity=(?P<severity>\S+) score=(?P<score>\S+) detail=(?P<detail>.*)$"
)

CATEGORY_LABELS = {
    "high_memory": "High Memory Usage",
    "leak_suspect": "Memory Leak Growth",
    "wx_pages": "WX Memory Page",
    "combined_risk": "Combined Risk (Multi-Indicator)",
    "memory_corruption_crash": "Memory Corruption Crash",
}

SEVERITY_MAP = {"critical": "CRITICAL", "warning": "WARNING", "info": "LOW"}

GROWTH_RE = re.compile(r"growing ~([\d.]+) MB/min")
SAMPLES_RE = re.compile(r"over (\d+) samples")

NUM_TREND_BUCKETS = 11


def parse_log(path: Path):
    findings = []
    if not path.exists():
        return findings
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = LINE_RE.match(line.strip())
            if m:
                findings.append(m.groupdict())
    return findings


def build_findings(raw_findings):
    findings = []
    for i, f in enumerate(raw_findings, start=1):
        detail = f["detail"]
        growth_m = GROWTH_RE.search(detail)
        samples_m = SAMPLES_RE.search(detail)
        try:
            score = int(float(f["score"]))
        except ValueError:
            score = 0
        sev = SEVERITY_MAP.get(f["severity"].lower(), "LOW")
        time_part = f["ts"].split(",")[0].split(" ")[-1]
        findings.append({
            "id": i,
            "time": time_part,
            "device": "this-machine",
            "process": f["name"],
            "pid": int(f["pid"]),
            "category": CATEGORY_LABELS.get(f["kind"], f["kind"]),
            "score": score,
            "severity": sev,
            "growthRate": f"+{growth_m.group(1)} MB/min" if growth_m else "n/a",
            "samples": int(samples_m.group(1)) if samples_m else 0,
            "baseline": "live rolling window",
        })
    return findings


def build_trend(findings):
    if not findings:
        return [0] * NUM_TREND_BUCKETS, [0] * NUM_TREND_BUCKETS
    scores = [f["score"] for f in findings]
    n = len(scores)
    trend, baseline = [], []
    for b in range(NUM_TREND_BUCKETS):
        lo = int(b * n / NUM_TREND_BUCKETS)
        hi = max(lo + 1, int((b + 1) * n / NUM_TREND_BUCKETS))
        bucket = scores[lo:hi] or [0]
        trend.append(max(bucket))
        baseline.append(round(sum(bucket) / len(bucket)))
    return trend, baseline


def main():
    parser = argparse.ArgumentParser(description="Generate the RAM-Guard security console HTML report")
    parser.add_argument("--log", default=str(Path(__file__).parent / "ram_guard.log"))
    parser.add_argument("--template", default=str(Path(__file__).parent / "security_console_template.html"))
    parser.add_argument("--out", default=str(Path(__file__).parent / "security_console.html"))
    args = parser.parse_args()

    raw_findings = parse_log(Path(args.log))
    findings = build_findings(raw_findings)
    trend, baseline = build_trend(findings)

    mem = psutil.virtual_memory()
    boot = datetime.fromtimestamp(psutil.boot_time())
    uptime_hours = round((datetime.now() - boot).total_seconds() / 3600, 2)
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    host_name = socket.gethostname()

    data = {
        "devices": [{"id": "this-machine", "name": host_name, "type": "desktop"}],
        "findings": findings,
        "trendSeries": trend,
        "baselineSeries": baseline,
    }

    template = Path(args.template).read_text(encoding="utf-8")
    output = (
        template
        .replace("__RAM_GUARD_DATA_JSON__", json.dumps(data))
        .replace("__HOST_NAME__", host_name)
        .replace("__GENERATED_AT__", generated_at)
        .replace("__TOTAL_RAM__", str(round(mem.total / (1024 ** 3), 1)))
        .replace("__RAM_USED_PCT__", str(mem.percent))
        .replace("__UPTIME_HOURS__", str(uptime_hours))
    )

    Path(args.out).write_text(output, encoding="utf-8")
    print(f"Wrote {args.out} — {len(findings)} findings from {args.log}")
    print(f"Open it directly in a browser (double-click, or 'start {args.out}' on Windows).")


if __name__ == "__main__":
    main()
