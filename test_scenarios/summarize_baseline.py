"""
summarize_baseline.py

Parses ram_guard.log after a passive/silent monitoring run and produces a
summary: how many findings fired, of what kind, on which processes, and how
often — the actual evidence needed to judge false-positive rate before
presenting this to anyone who might deploy it.

Usage:
    python test_scenarios/summarize_baseline.py
    python test_scenarios/summarize_baseline.py --log ../ram_guard.log
"""

import argparse
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

LINE_RE = re.compile(
    r"^(?P<ts>[\d\-]+ [\d:,]+) \| \w+\s+\| ram_guard\.\w+ \| "
    r"Process finding: pid=(?P<pid>\d+) name=(?P<name>\S+) kind=(?P<kind>\S+) "
    r"severity=(?P<severity>\S+) score=(?P<score>\S+) detail=(?P<detail>.*)$"
)

START_RE = re.compile(r"RAM-Guard starting up\. silent_mode=(\w+)")


def parse_log(path: Path):
    findings = []
    starts = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = LINE_RE.match(line.strip())
            if m:
                findings.append(m.groupdict())
                continue
            m2 = START_RE.search(line)
            if m2:
                ts = line.split("|")[0].strip()
                starts.append(ts)
    return findings, starts


def summarize(findings, starts, log_path: Path):
    if not findings:
        print("No findings recorded in this log yet.")
        if starts:
            print(f"Monitoring session(s) started at: {', '.join(starts)}")
        print("If you just started RAM-Guard, this is a good sign — let it "
              "run longer and re-run this summary later.")
        return

    first_ts = findings[0]["ts"]
    last_ts = findings[-1]["ts"]
    try:
        t0 = datetime.strptime(first_ts, "%Y-%m-%d %H:%M:%S,%f")
        t1 = datetime.strptime(last_ts, "%Y-%m-%d %H:%M:%S,%f")
        span_hours = (t1 - t0).total_seconds() / 3600
    except ValueError:
        span_hours = None

    by_kind = Counter(f["kind"] for f in findings)
    by_process = Counter(f["name"] for f in findings)
    by_kind_process = defaultdict(Counter)
    for f in findings:
        by_kind_process[f["kind"]][f["name"]] += 1

    print("=" * 60)
    print("RAM-GUARD BASELINE VALIDATION SUMMARY")
    print("=" * 60)
    print(f"Log file: {log_path}")
    print(f"Monitoring session(s) started: {len(starts)}")
    print(f"First finding: {first_ts}")
    print(f"Last finding:  {last_ts}")
    if span_hours is not None:
        print(f"Span covered: {span_hours:.1f} hours")
        if span_hours > 0.01:
            rate = len(findings) / span_hours
            print(f"Total findings: {len(findings)}  (~{rate:.1f} per hour)")
        else:
            print(f"Total findings: {len(findings)}  (span too short for a meaningful rate yet)")
    else:
        print(f"Total findings: {len(findings)}")
    print()

    print("Findings by type:")
    for kind, count in by_kind.most_common():
        print(f"  {kind:20s} {count}")
    print()

    print("Findings by process (top 10):")
    for name, count in by_process.most_common(10):
        print(f"  {name:30s} {count}")
    print()

    print("Breakdown (kind -> process -> count), for spotting a noisy repeat offender:")
    for kind, procs in by_kind_process.items():
        print(f"  [{kind}]")
        for name, count in procs.most_common(5):
            print(f"      {name:28s} {count}")
    print()

    print("-" * 60)
    print("How to read this:")
    print("- A process appearing many times under 'leak_suspect' but whose")
    print("  memory usage you know is normal (e.g. your browser) is a")
    print("  candidate for a config threshold adjustment, not a real leak.")
    print("- 'combined_risk' entries deserve the closest look — two")
    print("  independent indicators agreeing is the strongest signal here.")
    print("- Zero or near-zero findings over a multi-hour normal-use window")
    print("  is a good sign for the false-positive rate at current thresholds.")
    print("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Summarize a RAM-Guard baseline log")
    parser.add_argument("--log", default=str(Path(__file__).parent.parent / "ram_guard.log"))
    args = parser.parse_args()
    log_path = Path(args.log)
    if not log_path.exists():
        print(f"Log file not found: {log_path}")
        print("Make sure RAM-Guard has been run (python main.py --silent) before summarizing.")
    else:
        findings, starts = parse_log(log_path)
        summarize(findings, starts, log_path)
