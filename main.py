"""
RAM-Guard: RAM Vulnerability Detection & Alerting System
-----------------------------------------------------------
Entry point. Runs three complementary detection layers on a schedule:

  1. Live process memory monitor  -> catches leaks / abnormal usage /
                                      (best-effort) WX-page exploitation signs
  2. Known vulnerability catalogue -> reports host exposure to documented
                                      RAM-class vulnerabilities (Rowhammer,
                                      Meltdown/Spectre, cold-boot, DMA)
  3. Crash-signature monitor (Windows) -> catches application-level memory
                                      corruption (buffer overflow, use-after-
                                      free, double-free) at the moment it
                                      actually crashes a process, via Windows'
                                      own OS-confirmed exception codes

Findings from all three layers raise desktop notifications (with cooldown)
and are logged to file for later review / reporting.

Usage:
    python main.py                # run continuous monitoring loop
    python main.py --once         # run a single scan pass and exit
"""

import argparse
import logging
import sys
import time
from pathlib import Path

import yaml

from detector.process_monitor import ProcessMemoryMonitor
from detector.known_vulnerabilities import run_catalogue_scan
from detector.crash_monitor import CrashCorruptionMonitor
from notifier import Notifier


def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def setup_logging(cfg: dict):
    log_file = cfg["logging"]["log_file"]
    level = getattr(logging, cfg["logging"].get("level", "INFO").upper(), logging.INFO)

    # Findings text can contain non-ASCII characters (e.g. "->" arrows).
    # Windows consoles/files default to the system codepage (cp1252), which
    # can't encode them and would otherwise crash logging or corrupt the log.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )


def run_process_scan(monitor: ProcessMemoryMonitor, notifier: Notifier, logger, silent: bool = False):
    findings = monitor.scan_once()
    for f in findings:
        logger.info("Process finding: pid=%s name=%s kind=%s severity=%s score=%s detail=%s",
                    f.pid, f.name, f.kind, f.severity, f.risk_score, f.detail)
        if silent:
            continue
        notifier.notify(
            title=f"{f.kind.replace('_', ' ').title()} — {f.name} (PID {f.pid})",
            message=f.detail,
            key=f"proc:{f.pid}:{f.kind}",
            severity=f.severity,
        )
    return findings


def run_crash_scan(monitor: CrashCorruptionMonitor, notifier: Notifier, logger, silent: bool = False):
    findings = monitor.scan_once()
    for f in findings:
        logger.info("Crash finding: pid=%s name=%s kind=%s severity=%s score=%s detail=%s",
                    f.pid, f.name, f.kind, f.severity, f.risk_score, f.detail)
        if silent:
            continue
        notifier.notify(
            title=f"Memory Corruption Crash — {f.name} (PID {f.pid})",
            message=f.detail,
            key=f"crash:{f.pid}:{f.kind}",
            severity=f.severity,
        )
    return findings


def run_known_vuln_scan(notifier: Notifier, logger, silent: bool = False):
    results = run_catalogue_scan()
    for vc, res in results:
        status = "EXPOSED / REVIEW NEEDED" if res.exposed else "MITIGATED / NOT AFFECTED"
        logger.info("Catalogue check: %s (%s) -> %s | %s",
                    vc.name, vc.vuln_id, status, res.detail)
        if silent:
            continue
        if res.exposed:
            notifier.notify(
                title=f"{vc.name} ({vc.vuln_id})",
                message=f"{status}: {res.detail}",
                key=f"cat:{vc.vuln_id}",
                severity="info",
            )
    return results


def main():
    parser = argparse.ArgumentParser(description="RAM-Guard: RAM vulnerability detection & alerting")
    parser.add_argument("--once", action="store_true", help="Run a single scan pass and exit")
    parser.add_argument("--silent", action="store_true",
                         help="Log-only mode: no desktop/email/mobile alerts. "
                              "Use for passive baseline/false-positive validation runs.")
    parser.add_argument("--config", default=str(Path(__file__).parent / "config.yaml"))
    args = parser.parse_args()

    cfg = load_config(args.config)
    setup_logging(cfg)
    logger = logging.getLogger("ram_guard.main")

    silent = args.silent or cfg["logging"].get("silent_mode", False)

    mobile_cfg = cfg["notifications"].get("mobile_push", {})
    email_cfg = cfg["notifications"].get("email", {})
    notifier = Notifier(
        enabled=cfg["notifications"]["enabled"],
        cooldown_seconds=cfg["notifications"]["cooldown_seconds"],
        ntfy_topic=mobile_cfg.get("ntfy_topic"),
        ntfy_enabled=mobile_cfg.get("enabled", False),
        email_cfg=email_cfg,
    )
    monitor = ProcessMemoryMonitor(
        history_window=cfg["scan"]["history_window"],
        high_mem_pct=cfg["thresholds"]["high_memory_percent"],
        leak_mb_per_min=cfg["thresholds"]["leak_growth_mb_per_min"],
        min_samples=cfg["thresholds"]["min_samples_for_leak_check"],
        excluded_processes=cfg["thresholds"].get("excluded_processes", []),
    )
    crash_cfg = cfg.get("crash_monitor", {})
    crash_monitor = CrashCorruptionMonitor(
        lookback_minutes=crash_cfg.get("lookback_minutes", 10),
    )
    crash_enabled = crash_cfg.get("enabled", True)
    crash_interval = crash_cfg.get("check_interval_seconds", 30)

    logger.info("RAM-Guard starting up. silent_mode=%s", silent)
    last_catalogue_scan = 0.0
    catalogue_interval = cfg["known_vulnerability_scan"]["check_interval_seconds"]
    catalogue_enabled = cfg["known_vulnerability_scan"]["enabled"]

    if args.once:
        run_process_scan(monitor, notifier, logger, silent=silent)
        if catalogue_enabled:
            run_known_vuln_scan(notifier, logger, silent=silent)
        if crash_enabled:
            run_crash_scan(crash_monitor, notifier, logger, silent=silent)
        logger.info("Single scan complete.")
        return

    poll_interval = cfg["scan"]["poll_interval_seconds"]
    last_crash_scan = 0.0
    try:
        while True:
            run_process_scan(monitor, notifier, logger, silent=silent)
            if catalogue_enabled and (time.time() - last_catalogue_scan) >= catalogue_interval:
                run_known_vuln_scan(notifier, logger, silent=silent)
                last_catalogue_scan = time.time()
            if crash_enabled and (time.time() - last_crash_scan) >= crash_interval:
                run_crash_scan(crash_monitor, notifier, logger, silent=silent)
                last_crash_scan = time.time()
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        logger.info("RAM-Guard stopped by user.")


if __name__ == "__main__":
    main()
