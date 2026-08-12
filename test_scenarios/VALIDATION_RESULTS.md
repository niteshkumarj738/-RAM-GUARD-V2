# RAM-Guard — validation results

These are real, captured results from running RAM-Guard's detectors against
the controlled test scenarios in `test_scenarios/`, on this machine
(Linux, ~4 GB RAM), not projected or assumed behaviour.

## 1. High-memory detector

Scenario: `high_memory_hog.py --target-percent 20` (allocates ~800 MB of a
~4 GB system).

```
[high_memory_hog] PID=504 allocating 800 MB (~20.0% of 3998 MB total RAM)
Process finding: pid=504 name=python3 kind=high_memory
  detail=17.0% of system RAM (681 MB)
```

**Result: PASS.** Detected on the same PID the scenario reported, percentage
consistent with the amount actually allocated at scan time.

## 2. Leak-suspect detector

Scenario: `leak_simulator.py --mb-per-sec 0.8 --duration 35` (known,
steady growth rate).

```
Launched leak_simulator.py as PID 563
t=16s: LEAK DETECTED -> pid=563 name=python3
   detail: RSS growing ~43.9 MB/min over 4 samples (15→24 MB)
```

**Result: PASS.** Flagged within 4 scan samples, measured growth rate
(43.9 MB/min) consistent with the known simulated rate, above the
25 MB/min config threshold.

## 3. WX-page (writable+executable memory) detector

Scenario: `wx_page_demo.py` (maps one memory page as RWX in its own
process — no code ever written or executed in it).

```
Launched wx_page_demo.py as PID 567
DETECTED -> pid=567 name=python3 severity=critical
   detail: Writable+executable mapping at /dev/zero (perms=rwxs)
```

**Result: PASS.** Detected the exact permission pattern the detector is
designed to catch, correctly rated critical.

## 4. Combined risk scoring

Scenario: a faster leak (`--mb-per-sec 90`) engineered to cross **both**
the leak-rate threshold and the high-memory-percent threshold on the same
process, to test the escalation logic added on top of individual detection.

```
PID 599
t=10.0s  leak_suspect   severity=warning  score=35
t=12.5s  high_memory    severity=warning  score=25
t=12.5s  leak_suspect   severity=warning  score=35
t=12.5s  combined_risk  severity=warning  score=60
  detail: 2 indicators together (high_memory, leak_suspect) — combined risk score 60
```

**Result: PASS.** Both individual findings notified on their own (unchanged
behaviour), and the combined finding was raised in the same pass once two
distinct indicators co-occurred on the same PID, with a summed score
matching the two base weights (25 + 35 = 60).

## Summary

| Detector | Validated | Notes |
|---|---|---|
| High memory usage | ✅ | Matches known allocation |
| Leak-suspect growth | ✅ | Matches known simulated rate |
| WX page (exploit indicator) | ✅ | Linux-verified |
| Combined risk escalation | ✅ | Fires alongside individual alerts, not instead of |

## Honest scope of this validation

- Tested on Linux only (matches this development environment). The
  Windows/macOS code paths for the vulnerability catalogue are
  logically sound (registry/sysfs reads with graceful fallback) but
  weren't exercised on real Windows/macOS hardware — that's a fair
  thing to disclose if asked.
- These are self-triggered, controlled scenarios, not real-world
  malware or an actual exploit. They prove the detector logic works
  against the exact pattern it's designed for — they don't prove
  RAM-Guard would catch a sophisticated, evasive real attacker.
- The known-vulnerability catalogue (Rowhammer, Meltdown, cold boot, DMA)
  wasn't separately validated here since those checks read system state
  rather than react to a triggerable condition — they were exercised
  during normal scan runs shown earlier in this project.
