"""
adversarial_validation.py

Deliberately attempts to EVADE RAM-Guard's leak-suspect detector, instead
of triggering it cleanly like the other test_scenarios scripts do. This
imports and calls the same ProcessMemoryMonitor class main.py uses,
completely unmodified -- it does not weaken or special-case the detector
in any way. Results are real, captured, and reported honestly either way:
this is the difference between "the detector works against a cooperative
test" (already proven in VALIDATION_RESULTS.md) and "the detector holds up
against someone actively trying not to get caught," which is a materially
stronger and more honest claim for a security tool to be able to make.

Two evasion attempts:
  1. Low-and-slow leak -- grows memory steadily but deliberately below the
     configured leak_growth_mb_per_min threshold. Expected to EVADE: this
     documents a known, inherent limitation of any rate-threshold detector
     (there is always a rate below which it can't tell a slow leak from
     normal growth), not a bug to be fixed.
  2. Sawtooth leak -- grows fast (well above the rate threshold) but with
     periodic partial releases designed to break the ~75%-consistency
     requirement that was added after a real false-positive incident (see
     process_monitor.py). Tests whether an attacker who deliberately
     staggers allocation can defeat that specific check while still
     leaking at a high average rate. Outcome reported as observed, not
     assumed.

Usage:
    python test_scenarios/adversarial_validation.py
"""

import multiprocessing as mp
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import yaml

from detector.process_monitor import ProcessMemoryMonitor

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def _slow_leak_worker(mb_per_min, duration, ready_evt, stop_evt):
    chunks = []
    start = time.time()
    ready_evt.set()
    while time.time() - start < duration and not stop_evt.is_set():
        chunk = bytearray(max(1, int(mb_per_min * 1024 * 1024 / 60)))
        chunks.append(chunk)
        time.sleep(1)


def _sawtooth_leak_worker(mb_per_min, duration, dip_every, ready_evt, stop_evt):
    chunks = []
    start = time.time()
    ready_evt.set()
    tick = 0
    while time.time() - start < duration and not stop_evt.is_set():
        tick += 1
        if tick % dip_every == 0 and chunks:
            # Release about half of what's accumulated so far -- breaks the
            # "consistently upward" run without the overall trend ever
            # going net-negative across the test.
            del chunks[: len(chunks) // 2]
        else:
            chunk = bytearray(max(1, int(mb_per_min * 1024 * 1024 / 60)))
            chunks.append(chunk)
        time.sleep(1)


def run_evasion(name, worker_fn, worker_args, cfg, duration, poll_interval=1.0):
    ready = mp.Event()
    stop = mp.Event()
    proc = mp.Process(target=worker_fn, args=(*worker_args, ready, stop))
    proc.start()
    ready.wait(timeout=10)
    pid = proc.pid

    monitor = ProcessMemoryMonitor(
        history_window=cfg["scan"]["history_window"],
        high_mem_pct=cfg["thresholds"]["high_memory_percent"],
        leak_mb_per_min=cfg["thresholds"]["leak_growth_mb_per_min"],
        min_samples=cfg["thresholds"]["min_samples_for_leak_check"],
        excluded_processes=cfg["thresholds"].get("excluded_processes", []),
    )

    caught, caught_detail = False, None
    start = time.time()
    print(f"\n[{name}] target PID={pid}, running for up to {duration}s...")
    while time.time() - start < duration:
        for f in monitor.scan_once():
            if f.pid == pid and f.kind == "leak_suspect":
                caught, caught_detail = True, f.detail
                break
        if caught:
            break
        time.sleep(poll_interval)

    stop.set()
    proc.join(timeout=5)
    if proc.is_alive():
        proc.terminate()

    if caught:
        print(f"[{name}] RESULT: DETECTED -- {caught_detail}")
    else:
        print(f"[{name}] RESULT: EVADED -- no leak_suspect finding for PID {pid} "
              f"in {time.time() - start:.0f}s")
    return caught


def main():
    with open(Path(__file__).parent.parent / "config.yaml") as f:
        cfg = yaml.safe_load(f)

    threshold = cfg["thresholds"]["leak_growth_mb_per_min"]
    print("=" * 70)
    print("RAM-GUARD ADVERSARIAL VALIDATION -- real evasion attempts, real results")
    print("=" * 70)
    print(f"Configured leak-rate threshold: {threshold} MB/min | consistency requirement: 75%")

    results = {}
    results["low_and_slow"] = run_evasion(
        "low-and-slow leak", _slow_leak_worker,
        (threshold * 0.5, 40), cfg, duration=40,
    )
    results["sawtooth"] = run_evasion(
        "sawtooth leak", _sawtooth_leak_worker,
        (threshold * 3, 60, 3), cfg, duration=60,
    )

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    for name, caught in results.items():
        verdict = "DETECTED (evasion failed)" if caught else "EVADED (evasion succeeded)"
        print(f"  {name:20s} {verdict}")
    print()
    print("Interpretation:")
    print("- 'low-and-slow' evading is an EXPECTED, documented limitation of any")
    print("  rate-threshold detector, not a bug -- see README Design Notes.")
    print("- 'sawtooth' evading (if it happens) is a genuine finding: the")
    print("  75%-consistency check, added to kill real false positives, can also")
    print("  be defeated by an attacker who deliberately staggers allocation.")
    print("  Worth weighing against the false-positive rate as a real tradeoff,")
    print("  not treating either number as final.")
    print("=" * 70)


if __name__ == "__main__":
    main()
