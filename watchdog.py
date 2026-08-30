"""
watchdog.py

Independent process-health check for RAM-Guard: reads the heartbeat file
main.py writes once per scan cycle, and reports whether it's stale --
meaning the main monitoring loop appears to have stopped, crashed, or been
killed. Deliberately a separate process from main.py: if this check ran as
a thread inside main.py, a killed main.py process would silence the exact
thing that's supposed to notice main.py was killed. Meant to be scheduled
independently of the main process (see install_task.py), so it keeps
checking even when main.py doesn't.

This is a "someone/something killed the monitor" detector, not a general
intrusion-detection system -- it's the practical answer to "what stops
someone from just ending the python.exe process," which a plain script
with no supervision has no answer to at all.

Usage:
    python watchdog.py --once       # single check, for scheduled-task use
    python watchdog.py              # loop, checking every --interval seconds
"""

import argparse
import logging
import sys
import time
from pathlib import Path

import yaml

from notifier import Notifier

HEARTBEAT_FILE = Path(__file__).parent / ".ramguard_heartbeat"


def check_once(stale_after_seconds: float, notifier: Notifier, logger) -> bool:
    """Returns True if RAM-Guard's main loop looks alive, False otherwise."""
    if not HEARTBEAT_FILE.exists():
        logger.warning("Watchdog: no heartbeat file found -- RAM-Guard's main loop may "
                        "never have started, or was started before this heartbeat existed.")
        return False
    try:
        last_beat = float(HEARTBEAT_FILE.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        logger.warning("Watchdog: heartbeat file unreadable or corrupt.")
        return False

    age = time.time() - last_beat
    if age > stale_after_seconds:
        logger.error("Watchdog: heartbeat is %.0fs old (threshold %.0fs) -- "
                      "main monitoring loop appears to have stopped.", age, stale_after_seconds)
        notifier.notify(
            title="RAM-Guard Monitor Stopped",
            message=(f"No heartbeat for {age:.0f}s -- the main monitoring process appears "
                      f"to have crashed, been killed, or stopped unexpectedly."),
            key="watchdog:stale",
            severity="critical",
        )
        return False

    logger.info("Watchdog: heartbeat OK (%.0fs old).", age)
    return True


def setup_logging(cfg: dict):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        handlers=[
            logging.FileHandler(cfg["logging"]["log_file"], encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )


def main():
    parser = argparse.ArgumentParser(
        description="RAM-Guard watchdog: detects if the main monitor process has stopped")
    parser.add_argument("--once", action="store_true", help="Single check and exit (for scheduled-task use)")
    parser.add_argument("--interval", type=float, default=60.0, help="Seconds between checks in loop mode")
    parser.add_argument("--config", default=str(Path(__file__).parent / "config.yaml"))
    args = parser.parse_args()

    with open(args.config) as f:
        cfg = yaml.safe_load(f)
    setup_logging(cfg)
    logger = logging.getLogger("ram_guard.watchdog")

    # A single missed cycle can just be a slow scan; 3 missed cycles plus a
    # margin is a much stronger "this actually stopped" signal, not a
    # threshold tuned to the second.
    stale_after = cfg["scan"]["poll_interval_seconds"] * 3 + 30

    mobile_cfg = cfg["notifications"].get("mobile_push", {})
    email_cfg = cfg["notifications"].get("email", {})
    notifier = Notifier(
        enabled=cfg["notifications"]["enabled"],
        cooldown_seconds=cfg["notifications"]["cooldown_seconds"],
        ntfy_topic=mobile_cfg.get("ntfy_topic"),
        ntfy_enabled=mobile_cfg.get("enabled", False),
        email_cfg=email_cfg,
    )

    if args.once:
        check_once(stale_after, notifier, logger)
        return

    while True:
        check_once(stale_after, notifier, logger)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
