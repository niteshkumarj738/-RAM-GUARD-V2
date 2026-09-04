"""
RAM-Guard: RAM Vulnerability Detection & Alerting System
-----------------------------------------------------------
Entry point. Runs four complementary detection layers on a schedule:

  1. Live process memory monitor  -> catches leaks / abnormal usage /
                                      (best-effort) WX-page exploitation signs
  2. Known vulnerability catalogue -> reports host exposure to documented
                                      speculative-execution / RAM-disclosure
                                      CPU vulnerabilities (Meltdown/Spectre,
                                      MDS, L1TF) and DMA attacks
  3. Crash-signature monitor (Windows) -> catches application-level memory
                                      corruption (buffer overflow, use-after-
                                      free, double-free) at the moment it
                                      actually crashes a process, via Windows'
                                      own OS-confirmed exception codes
  4. Signature scan -> matches installed software / host config against a
                                      static, offline catalogue of named,
                                      documented CVEs (see
                                      detector/signature_scan.py)

Findings from all four layers are logged to file for later review /
reporting. Desktop/mobile/email alerts fire on every signature-scan match
(a version match against a named CVE is a fact, not a guess) and on
critical-severity findings from the process and crash monitors; the
known-vulnerability catalogue is log-only (see run_known_vuln_scan).

Usage:
    python main.py                # run continuous monitoring loop
    python main.py --once         # run a single scan pass and exit
"""

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path

import yaml

from detector.process_monitor import ProcessMemoryMonitor
from detector.known_vulnerabilities import run_catalogue_scan
from detector.crash_monitor import CrashCorruptionMonitor
from detector.signature_scan import run_signature_scan
from fleet_reporting import FleetReporter
from log_integrity import HashChainHandler
from notifier import Notifier

HEARTBEAT_FILE = Path(__file__).parent / ".ramguard_heartbeat"


def write_heartbeat():
    """Written once per scan cycle so process_watchdog.py -- a separate, independently
    scheduled process -- can tell whether this loop is still alive. Doing
    this as a file check rather than an in-process thread is deliberate: a
    watchdog that shares main.py's process would go silent at the exact
    moment main.py is killed, which is the one moment it needs to speak up."""
    try:
        HEARTBEAT_FILE.write_text(str(time.time()), encoding="utf-8")
    except OSError:
        pass


def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def load_catalogue_status(path: Path) -> dict:
    """Persists which vuln IDs were already exposed, across process
    restarts and separate --once invocations, so an unchanging exposure
    status doesn't re-notify every time the tool is run."""
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save_catalogue_status(path: Path, status: dict):
    try:
        path.write_text(json.dumps(status), encoding="utf-8")
    except OSError:
        pass


def setup_logging(cfg: dict):
    log_file = cfg["logging"]["log_file"]
    level = getattr(logging, cfg["logging"].get("level", "INFO").upper(), logging.INFO)

    # Findings text can contain non-ASCII characters (e.g. "->" arrows).
    # Windows consoles/files default to the system codepage (cp1252), which
    # can't encode them and would otherwise crash logging or corrupt the log.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    hash_handler = HashChainHandler(log_file + ".hashes")
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        handlers=[
            logging.FileHandler(log_file, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
            hash_handler,
        ],
    )


def run_process_scan(monitor: ProcessMemoryMonitor, notifier: Notifier, logger, fleet: FleetReporter, silent: bool = False):
    findings = monitor.scan_once()
    for f in findings:
        logger.info("Process finding: pid=%s name=%s kind=%s severity=%s score=%s detail=%s",
                    f.pid, f.name, f.kind, f.severity, f.risk_score, f.detail)
        # Fleet reporting isn't gated by --silent: --silent only suppresses
        # local desktop/mobile/email interruptions on this machine, it isn't
        # meant to hide findings from a central collector a fleet deployment
        # relies on instead of local popups.
        fleet.report("process", {"pid": f.pid, "name": f.name, "kind": f.kind,
                                  "severity": f.severity, "score": f.risk_score, "detail": f.detail})
        if silent:
            continue
        # Every finding is still logged (and visible in the dashboard/console)
        # regardless of severity -- only CRITICAL findings interrupt with a
        # popup/mobile/email alert. A lone high-memory or leak-suspect hit is
        # "warning": worth a look, not urgent enough to interrupt. Combined
        # multi-indicator risk, real crashes, and Linux WX-pages are the
        # ones that actually escalate to critical.
        if f.severity != "critical":
            continue
        notifier.notify(
            title=f"{f.kind.replace('_', ' ').title()} — {f.name} (PID {f.pid})",
            message=f.detail,
            key=f"proc:{f.pid}:{f.kind}",
            severity=f.severity,
        )
    return findings


def run_crash_scan(monitor: CrashCorruptionMonitor, notifier: Notifier, logger, fleet: FleetReporter, silent: bool = False):
    findings = monitor.scan_once()
    for f in findings:
        logger.info("Crash finding: pid=%s name=%s kind=%s severity=%s score=%s detail=%s",
                    f.pid, f.name, f.kind, f.severity, f.risk_score, f.detail)
        fleet.report("crash", {"pid": f.pid, "name": f.name, "kind": f.kind,
                                "severity": f.severity, "score": f.risk_score, "detail": f.detail})
        if silent:
            continue
        # Only critical findings interrupt with a popup/mobile/email alert,
        # consistent with the process scan below. Crash findings are always
        # critical by construction (OS-confirmed corruption), but the check
        # is kept explicit rather than assumed.
        if f.severity != "critical":
            continue
        notifier.notify(
            title=f"Memory Corruption Crash — {f.name} (PID {f.pid})",
            message=f.detail,
            key=f"crash:{f.pid}:{f.kind}",
            severity=f.severity,
        )
    return findings


def run_known_vuln_scan(logger, fleet: FleetReporter, last_status: dict = None):
    """Runs the catalogue check every cycle (so the log/dashboard always
    reflect current status). Catalogue exposures are host configuration
    facts, not an active in-progress threat, so this never pops a
    popup/mobile/email alert -- only critical findings from the
    process/crash scans do that. Still logged every cycle either way, and
    last_status is kept up to date for callers that want to track exposure
    changes over time."""
    if last_status is None:
        last_status = {}
    results = run_catalogue_scan()
    for vc, res in results:
        status = "EXPOSED / REVIEW NEEDED" if res.exposed else "MITIGATED / NOT AFFECTED"
        logger.info("Catalogue check: %s (%s) -> %s | %s",
                    vc.name, vc.vuln_id, status, res.detail)
        fleet.report("catalogue", {"vuln_id": vc.vuln_id, "name": vc.name,
                                    "status": status, "detail": res.detail})
        last_status[vc.vuln_id] = res.exposed
    return results


def run_signature_scan_pass(notifier: Notifier, logger, fleet: FleetReporter, silent: bool = False):
    """Static, offline signature matching: installed software / host config
    against a local catalogue of real, named CVEs (see
    detector/signature_scan.py). Unlike every other scan in this file, this
    ALWAYS notifies on a match, at whatever severity the signature carries
    -- a version match against a named CVE is a concrete fact about the
    host, not a probabilistic behavioural signal like the process monitor's
    findings, so it isn't gated to critical-only."""
    findings = run_signature_scan()
    for f in findings:
        logger.info("Signature finding: sig_id=%s cve=%s name=%s severity=%s detail=%s",
                    f.sig_id, f.cve_id, f.name, f.severity, f.detail)
        fleet.report("signature", {"sig_id": f.sig_id, "cve_id": f.cve_id, "name": f.name,
                                    "severity": f.severity, "detail": f.detail})
        if silent:
            continue
        notifier.notify(
            title=f"{f.name} ({f.cve_id})",
            message=f.detail,
            key=f"sig:{f.sig_id}",
            severity=f.severity,
        )
    return findings


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
    # The app password comes from an environment variable, never from
    # config.yaml -- config.yaml is tracked in git and pushed to a public
    # repo, so a real credential written into it would leak. Falls back to
    # whatever's in config.yaml only if the env var isn't set, so a purely
    # local/offline setup that never pushes still works either way.
    env_password = os.environ.get("RAMGUARD_EMAIL_APP_PASSWORD")
    if env_password:
        email_cfg = {**email_cfg, "sender_app_password": env_password}
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

    signature_cfg = cfg.get("signature_scan", {})
    signature_enabled = signature_cfg.get("enabled", True)
    signature_interval = signature_cfg.get("check_interval_seconds", 3600)

    fleet_cfg = cfg.get("fleet_reporting", {})
    fleet = FleetReporter(
        enabled=fleet_cfg.get("enabled", False),
        collector_url=fleet_cfg.get("collector_url", ""),
        device_id=fleet_cfg.get("device_id", ""),
        api_key=fleet_cfg.get("api_key", ""),
    )

    logger.info("RAM-Guard starting up. silent_mode=%s", silent)
    last_catalogue_scan = 0.0
    catalogue_interval = cfg["known_vulnerability_scan"]["check_interval_seconds"]
    catalogue_enabled = cfg["known_vulnerability_scan"]["enabled"]
    status_path = Path(__file__).parent / ".catalogue_status.json"
    catalogue_status = load_catalogue_status(status_path)

    if args.once:
        run_process_scan(monitor, notifier, logger, fleet, silent=silent)
        if catalogue_enabled:
            run_known_vuln_scan(logger, fleet, last_status=catalogue_status)
            save_catalogue_status(status_path, catalogue_status)
        if crash_enabled:
            run_crash_scan(crash_monitor, notifier, logger, fleet, silent=silent)
        if signature_enabled:
            run_signature_scan_pass(notifier, logger, fleet, silent=silent)
        logger.info("Single scan complete.")
        return

    poll_interval = cfg["scan"]["poll_interval_seconds"]
    last_crash_scan = 0.0
    last_signature_scan = 0.0
    write_heartbeat()
    try:
        while True:
            write_heartbeat()
            run_process_scan(monitor, notifier, logger, fleet, silent=silent)
            if catalogue_enabled and (time.time() - last_catalogue_scan) >= catalogue_interval:
                run_known_vuln_scan(logger, fleet, last_status=catalogue_status)
                save_catalogue_status(status_path, catalogue_status)
                last_catalogue_scan = time.time()
            if crash_enabled and (time.time() - last_crash_scan) >= crash_interval:
                run_crash_scan(crash_monitor, notifier, logger, fleet, silent=silent)
                last_crash_scan = time.time()
            if signature_enabled and (time.time() - last_signature_scan) >= signature_interval:
                run_signature_scan_pass(notifier, logger, fleet, silent=silent)
                last_signature_scan = time.time()
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        logger.info("RAM-Guard stopped by user.")


if __name__ == "__main__":
    main()
