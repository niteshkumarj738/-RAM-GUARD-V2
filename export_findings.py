"""
export_findings.py

Exports every RAM-Guard finding parsed from ram_guard.log -- process/leak/
WX-page findings, memory-corruption crash signatures, known-vulnerability
catalogue checks, and CVE signature matches -- to CSV and/or JSON, for
handing off to a spreadsheet or an external trend-analysis tool. Read-only
against the log; does not run any scan itself, same pattern as
test_scenarios/summarize_baseline.py and generate_security_console.py.

Usage:
    python export_findings.py
    python export_findings.py --log ram_guard.log --out findings_export --format csv,json
"""

import argparse
import csv
import json
import re
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PROCESS_CRASH_RE = re.compile(
    r"^(?P<ts>[\d\-]+ [\d:,]+) \| \w+\s+\| ram_guard\.\w+ \| "
    r"(?P<source>Process|Crash) finding: pid=(?P<pid>\d+) name=(?P<name>\S+) kind=(?P<kind>\S+) "
    r"severity=(?P<severity>\S+) score=(?P<score>\S+) detail=(?P<detail>.*)$"
)

SIGNATURE_RE = re.compile(
    r"^(?P<ts>[\d\-]+ [\d:,]+) \| \w+\s+\| ram_guard\.\w+ \| "
    r"Signature finding: sig_id=(?P<sig_id>\S+) cve=(?P<cve>.+?) name=(?P<name>.+?) "
    r"severity=(?P<severity>\S+) detail=(?P<detail>.*)$"
)

CATALOGUE_RE = re.compile(
    r"^(?P<ts>[\d\-]+ [\d:,]+) \| \w+\s+\| ram_guard\.\w+ \| "
    r"Catalogue check: (?P<name>.+?) \((?P<id>RG-\d+)\) -> "
    r"(?P<status>EXPOSED / REVIEW NEEDED|MITIGATED / NOT AFFECTED) \| (?P<detail>.*)$"
)

FIELDNAMES = ["timestamp", "layer", "id", "process_or_name", "pid",
              "category", "severity", "score", "detail"]


def parse_log(path: Path):
    records = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()

            m = PROCESS_CRASH_RE.match(line)
            if m:
                layer = "crash" if m.group("kind") == "memory_corruption_crash" else "process"
                records.append({
                    "timestamp": m.group("ts"), "layer": layer, "id": "",
                    "process_or_name": m.group("name"), "pid": m.group("pid"),
                    "category": m.group("kind"), "severity": m.group("severity"),
                    "score": m.group("score"), "detail": m.group("detail"),
                })
                continue

            m = SIGNATURE_RE.match(line)
            if m:
                records.append({
                    "timestamp": m.group("ts"), "layer": "signature", "id": m.group("sig_id"),
                    "process_or_name": m.group("cve"), "pid": "",
                    "category": m.group("name"), "severity": m.group("severity"),
                    "score": "", "detail": m.group("detail"),
                })
                continue

            m = CATALOGUE_RE.match(line)
            if m:
                records.append({
                    "timestamp": m.group("ts"), "layer": "catalogue", "id": m.group("id"),
                    "process_or_name": m.group("name"), "pid": "",
                    "category": m.group("status"), "severity": "",
                    "score": "", "detail": m.group("detail"),
                })
                continue
    return records


def write_csv(records, path: Path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(records)


def write_json(records, path: Path):
    path.write_text(json.dumps(records, indent=2), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Export RAM-Guard findings to CSV/JSON")
    parser.add_argument("--log", default=str(Path(__file__).parent / "ram_guard.log"))
    parser.add_argument("--out", default=str(Path(__file__).parent / "findings_export"),
                         help="Output path prefix, without extension")
    parser.add_argument("--format", default="csv,json", help="Comma-separated: csv,json")
    args = parser.parse_args()

    log_path = Path(args.log)
    if not log_path.exists():
        print(f"Log file not found: {log_path}")
        print("Make sure RAM-Guard has been run (python main.py --once) before exporting.")
        return

    records = parse_log(log_path)
    formats = {f.strip().lower() for f in args.format.split(",")}

    if "csv" in formats:
        csv_path = Path(f"{args.out}.csv")
        write_csv(records, csv_path)
        print(f"Wrote {csv_path} ({len(records)} records)")
    if "json" in formats:
        json_path = Path(f"{args.out}.json")
        write_json(records, json_path)
        print(f"Wrote {json_path} ({len(records)} records)")


if __name__ == "__main__":
    main()
