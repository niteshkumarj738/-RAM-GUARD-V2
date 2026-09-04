# RAM-Guard — validation results

These are real, captured results from running RAM-Guard's detectors against
the controlled test scenarios in `test_scenarios/`, not projected or assumed
behaviour. Section 1-4 below are from the original Linux development
environment (~4 GB RAM); the Windows section further down covers a second,
separate validation pass on the actual Windows deployment target, including
a real multi-hour false-positive finding and fix.

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
| High memory usage | ✅ | Matches known allocation, Linux + Windows |
| Leak-suspect growth | ✅ | Fixed a real ~489/hour false-positive rate found in a 7h live run; re-validated after fix |
| WX page (exploit indicator) | ✅ | Linux + Windows (`VirtualQueryEx`); noisy on JIT-using Windows apps by nature, documented |
| Combined risk escalation | ✅ | Fires alongside individual alerts, not instead of |
| Desktop notification | ✅ | Confirmed visible on-screen, Windows |
| Mobile push (ntfy) | ⚠️ | Server-side confirmed working; phone delivery blocked by Android background restrictions (device-side, not a code issue) |
| Memory-corruption crash signatures (Windows) | ✅ | Validated against 6 real historical crashes on this machine; correctly excluded 191 unrelated .NET exceptions |

## Windows validation (real deployment target)

Everything below was run live on the actual Windows machine this tool is
meant to run on, separately from the Linux dev-environment results above.

### 5. High-memory + WX-page detector on Windows

The WX-page (writable+executable memory) check originally only worked on
Linux; on Windows it silently detected nothing. Implemented a real Windows
equivalent using `VirtualQueryEx` to walk each flagged process's address
space for `PAGE_EXECUTE_READWRITE` / `PAGE_EXECUTE_WRITECOPY` regions.

```
[high_memory_hog] PID=26348 allocating 2571 MB (~16.0% of 16069 MB total RAM)
Process finding: pid=26348 name=python.exe kind=high_memory
  detail=16.1% of system RAM (2588 MB)
```
**Result: PASS.** Matches the target allocation, same as the Linux result.

WX-page scan, run against real running system processes (not synthetic):
```
Process finding: pid=18740 name=Code.exe kind=wx_pages severity=warning
  detail=Writable+executable memory region at 0x7FF6E0040000 (11272192 bytes)
Process finding: pid=32132 name=chrome.exe kind=wx_pages severity=warning
  detail=Writable+executable memory region at 0x7FF8CF4C0000 (92274688 bytes)
```
**Result: PASS, with an honest caveat.** The scan correctly finds real WX
regions — but VS Code, Chrome, and Edge WebView2 all legitimately hold WX
memory for their JIT compilers (V8/Electron/.NET), so this indicator is
noisy by nature on Windows once a JIT-using app crosses the memory
threshold. Documented in the main README rather than hidden; severity was
set to `warning` (not `critical`) specifically because of this.

### 6. Desktop + mobile notification pipeline

Triggered a real finding end-to-end (not just logged): desktop popup
confirmed visible on-screen; mobile push via ntfy.sh confirmed reaching the
server correctly (after fixing a header-encoding bug — em dashes in finding
titles crashed the request under Latin-1 HTTP header encoding until the
title was sent as raw UTF-8 bytes). Delivery to the phone's ntfy app itself
was blocked by Android background-restriction settings, a device-side
limitation rather than a code defect — email alerts were chosen as the more
reliable phone-notification channel going forward.

### 7. Leak-suspect false-positive discovery and fix (real 7-hour run)

Ran RAM-Guard in `--silent` (log-only) baseline mode on real, ordinary
laptop use — not a synthetic scenario — for **7 hours**.

```
Total findings: 3,444  (~489/hour)
Findings by type: leak_suspect  3,431   high_memory  12   combined_risk  1
Top offenders:    chrome.exe 965   OCControl.Service.exe 624
                   MemCompression 521   msedgewebview2.exe 389   Code.exe 151
```
**Result: the leak detector was unusably noisy as originally built.**
Comparing only the first and last sample in the window let ordinary
spike-and-release memory behaviour (browsers, the OS memory compressor)
average out to the same rate as a real leak.

**Fix:** require ~75% of the sample window to be trending upward, not just
the two endpoints — a real leak grows steadily; ordinary apps don't.

**Re-validation after the fix**, real leak scenario + real system running
concurrently for 80 seconds:
```
Process finding: pid=8488 name=python.exe kind=leak_suspect
  detail=RSS growing ~36.8 MB/min over 12 samples (32→57 MB), 100% consistently upward
```
Chrome, MemCompression, and Edge WebView2 — the three biggest offenders
above — produced **zero** false positives in the follow-up run. VS Code
(`Code.exe`) still showed some residual noise, which is reported here
rather than omitted; further tuning is a reasonable next step, not a
solved problem.

### 8. Memory-corruption crash-signature detector (Windows)

Rather than a synthetic trigger, this was validated against **real crash
history already present on this machine's Windows Application Event Log**
— a stronger form of evidence than a self-triggered demo, since these
crashes happened naturally, independent of anything built for this project.

A survey of the last 200 "Application Error" (Event ID 1000) events on this
machine found 2 real access violations and 4 real stack buffer overruns
among them (191 others were unrelated .NET managed exceptions, correctly
excluded — see below).

```
Found 6 memory-corruption-class crash findings:
  pid=9444  name=RtkAudUService64.exe   exception=0xc0000005 (access violation)
  pid=3452  name=NVDisplay.Container.exe exception=0xc0000409 (stack buffer overrun)
  pid=17956 name=mc-wns-client.exe      exception=0xc0000409 (stack buffer overrun)
  pid=7472  name=explorer.exe           exception=0xc0000005 (access violation)
  pid=25820 name=mc-wns-client.exe      exception=0xc0000409 (stack buffer overrun)
  pid=5792  name=mc-wns-client.exe      exception=0xc0000409 (stack buffer overrun)
```

**Result: PASS.** All 6 real corruption-class crashes were correctly
identified with the right process name, PID, and exception meaning.

**Negative-case check, equally important:** the same machine's crash
history also includes 191 events with exception code `0xe0434352` (a .NET
CLR managed exception — not a memory-safety bug in the C/C++ sense). The
detector correctly excluded all of them, since only specific memory-
corruption exception codes are treated as findings. This matters as much
as the positive result: a detector that flagged every crash indiscriminately
would be as useless as the pre-fix leak detector was.

### 9. Adversarial validation — deliberate evasion attempts, not cooperative tests

Sections 1-8 above all validate detection against scenarios *designed to
trigger* the detector. `test_scenarios/adversarial_validation.py` instead
tries to *evade* the leak-suspect detector, calling the same unmodified
`ProcessMemoryMonitor` class `main.py` uses. Two real attempts, real
captured results:

```
[low-and-slow leak] target PID=27328, running for up to 40s...
[low-and-slow leak] RESULT: EVADED -- no leak_suspect finding for PID 27328 in 42s

[sawtooth leak] target PID=5592, running for up to 60s...
[sawtooth leak] RESULT: DETECTED -- RSS growing ~32.5 MB/min over 5 samples
  (30->33 MB), 100% consistently upward
```

**Result 1 — low-and-slow (growth held deliberately below the 25 MB/min
threshold): evasion succeeded.** This is an expected, inherent limitation
of any rate-threshold detector, not a bug — there is always some growth
rate below which it cannot be distinguished from normal usage. Documented
here rather than treated as a gap that was missed.

**Result 2 — sawtooth (fast growth with deliberate periodic partial
releases, designed to break the 75%-consistency requirement added after
the false-positive fix in section 7): evasion failed, detection held.**
Caught within the first 5 samples in this run, before a scheduled dip
landed inside the sampling window. **Caveat, stated honestly:** this
result is timing-sensitive — whether a dip lands inside the detector's
sample window before `min_samples` is reached depends on the relative
timing between the attacker's dip schedule and the scan interval. A single
run passing doesn't prove the consistency check can't be defeated by a
differently-timed attacker; it proves it wasn't defeated by *this*
attempt. Worth more runs with varied timing before treating this as a
settled result either way.

## Honest scope of this validation

- Sections 1-4 (Linux) and 5-7 (Windows) were both run for real, on real
  hardware — not projected or assumed. macOS was not tested; the
  vulnerability-catalogue code paths for it are logically sound (documented
  fallback to manual review where no API exists) but unexercised.
- These are self-triggered, controlled scenarios (plus one real multi-hour
  passive run and, in section 9, two real evasion attempts), not
  real-world malware or an actual exploit. They prove the detector logic
  works against the exact pattern it's designed for, holds up against at
  least one deliberate evasion attempt, and — for the 7-hour run — against
  real ordinary usage. They don't prove RAM-Guard would catch a
  sophisticated, sustained, real evasive attacker — section 9's own caveat
  about timing-sensitivity is a concrete example of why that claim still
  isn't earned.
- The known-vulnerability catalogue (Meltdown/Spectre, MDS, L1TF, DMA)
  wasn't separately validated here since those checks read system state
  rather than react to a triggerable condition — they were exercised
  during normal scan runs shown earlier in this project, on both Linux and
  Windows. Rowhammer and cold-boot were deliberately removed from the
  catalogue (see README) rather than represented as checked.
