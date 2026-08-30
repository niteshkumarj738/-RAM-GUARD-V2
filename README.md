# RAM-Guard — RAM Vulnerability Detection & Alerting System

A lightweight, host-based tool that flags suspicious memory activity and
indicators associated with known RAM-related security risks, then raises
real-time desktop alerts. Built as a defensive monitoring utility —
it flags risk indicators for review; it does not exploit anything.

**Important framing note:** this tool does not claim "we detect RAM attacks."
A single signal (e.g. high memory usage) does not prove an attack — plenty
of normal programs use a lot of RAM. What it actually does is flag
*indicators* that correlate with known attack patterns, and — as of the
risk-scoring layer below — treats multiple indicators occurring together on
the same process as more meaningful than any single one alone.

## What it detects

**1. Live process memory anomalies** (`detector/process_monitor.py`)
- Abnormally high single-process RAM usage
- Sustained memory growth consistent with a leak (RSS growth rate over a
  rolling sample window)
- (Best-effort, Linux) memory pages that are simultaneously writable and
  executable — a classic indicator of in-memory code injection / an
  exploited buffer overflow

**2. Known RAM-class vulnerability exposure** (`detector/known_vulnerabilities.py`)
A reference catalogue with non-invasive host checks for:
| ID | Vulnerability | Category |
|----|---------------|----------|
| RG-001 | Rowhammer | Hardware / DRAM bit-flip |
| RG-002 | Meltdown / Spectre | Speculative-execution RAM disclosure |
| RG-003 | Cold Boot Attack | Physical / RAM remanence |
| RG-004 | DMA Attack | Physical / peripheral RAM access |

Where software cannot conclusively verify exposure (e.g. Rowhammer depends
on DRAM refresh timing, cold-boot depends on physical access policy), the
tool flags it explicitly as "review needed" rather than guessing.

**3. Application-level memory corruption crashes, Windows only**
(`detector/crash_monitor.py`) — watches the Windows Application Event Log
for process crashes whose exception code is a direct, OS-confirmed
memory-corruption signature:
| Exception code | Meaning |
|---|---|
| `0xc0000005` | Access violation — often a use-after-free, buffer overflow, or null-deref |
| `0xc0000374` | Heap corruption, detected by Windows' own heap manager — a strong double-free / heap-overflow signature |
| `0xc0000409` | Stack buffer overrun — the compiler's `/GS` canary caught a stack overflow |

**Scope boundary, stated plainly:** this does not find buffer overflows,
use-after-free, or double-free bugs *in source code before they happen* —
that requires static analysis (Coverity, Clang Static Analyzer) or
instrumented builds (AddressSanitizer, Valgrind), a different category of
tool that needs the target program's source or a special build. This
catches the moment such a bug actually corrupts memory badly enough to
crash a process, using Windows' own exception system as the authority —
a black-box, after-the-fact signal, consistent with how the rest of
RAM-Guard works.

**4. Signature-based CVE detection** (`detector/signature_scan.py`) —
matches installed software and known-risky host configuration against a
static, offline catalogue of **named, documented CVEs**, entirely local —
no network calls, no live feed. Two signature types:

| Type | How it matches | Example |
|---|---|---|
| `software_version` | Installed program version (read from the Windows Uninstall registry — the same data Control Panel reads) at or below a known-vulnerable version | WinRAR < 5.70 → CVE-2018-20250 (ACE extraction RCE) |
| `host_config` | A specific, checkable host setting that is the documented defense-in-depth mitigation for a named CVE, independent of patch level | SMBv1 enabled → CVE-2017-0144 (EternalBlue exposure class) |

Full current catalogue (5 signatures): WinRAR ACE RCE (CVE-2018-20250),
7-Zip heap overflow (CVE-2016-2334/2335), VLC heap over-read
(CVE-2019-13615), SMBv1-enabled (CVE-2017-0144/MS17-010), and
RDP-without-NLA (CVE-2019-0708/BlueKeep). Each entry's severity comes from
the CVE itself, not a hardcoded default.

**This layer behaves differently from the other three, on purpose:** every
signature match notifies immediately, regardless of severity. A version
match against a named CVE is a *fact* about the host — not a probabilistic
behavioural signal like "this process is using a lot of RAM" — so it isn't
gated to critical-only the way the process/crash monitors are.

## Architecture

```
main.py            Orchestrator: runs all detection layers on a schedule
detector/
  process_monitor.py       Live per-process RAM anomaly detection
  known_vulnerabilities.py Static catalogue + host exposure checks
  crash_monitor.py         Windows Event Log memory-corruption crash signatures
  signature_scan.py        Static, offline catalogue of named CVEs matched against
                            installed software / host config — always notifies on a match
notifier.py         Cross-platform desktop popup + instant mobile push via ntfy.sh (with cooldown)
dashboard.py         Streamlit dashboard for live visualization
config.yaml          All thresholds / intervals in one place
```

## Setup

```bash
pip install -r requirements.txt
```

## Running

**Continuous monitoring (with desktop popups):**
```bash
python main.py
```

**Single scan pass (for scripting / CI / cron):**
```bash
python main.py --once
```

**Silent baseline mode (log only, no alerts — for validation runs):**
```bash
python main.py --silent
```

**Dashboard view:**
```bash
streamlit run dashboard.py
```

## Mobile push alerts (ntfy.sh)

No account needed on either end — a shared "topic" name is the only secret.

1. Install the **ntfy** app (Android/iOS) from the store.
2. In the app, subscribe to a topic name only you know, e.g. `nitesh-ramguard-7x2k`.
3. In `config.yaml`, set:
   ```yaml
   notifications:
     mobile_push:
       enabled: true
       ntfy_topic: "nitesh-ramguard-7x2k"
   ```
4. That's it — every alert now hits your phone as an instant push, at the
   same time as the desktop popup.

Keep the topic name reasonably unique/unguessable — ntfy topics are public
by name (anyone who knows the exact topic string can subscribe to it), it's
"security by unguessable name," not authentication.

## Email alerts (no app needed)

Alerts land as a normal email, which triggers your phone's built-in
notification through whatever mail app you already have.

1. Go to your Google Account → Security → **2-Step Verification** (must be
   turned on first).
2. Under Security, search **"App passwords"** → create one for "Mail" →
   Google gives you a 16-character password (different from your login
   password).
3. In `config.yaml`, fill in:
   ```yaml
   notifications:
     email:
       enabled: true
       sender_email: "your.email@gmail.com"
       sender_app_password: "the 16-char app password"
       recipient_email: "your.email@gmail.com"   # or a different phone's email
   ```
4. Done — every alert now also sends an email, which pops up on your phone
   like any other notification.

Never use your real Gmail login password here — only the generated app
password. If you don't want to touch your main Gmail, create a free
throwaway Gmail just for this tool to send from.

## Risk scoring (combined indicators)

Every individual finding still notifies immediately on its own, exactly as
before — nothing is delayed or suppressed waiting for corroboration.

On top of that, if **two or more different indicators** fire on the **same
process in the same scan pass** (e.g. high memory usage *and* fast growth
*and* a WX page, together), an additional `combined_risk` finding is raised
with a summed score:

| Indicator | Base score |
|---|---|
| High memory usage | 25 |
| Leak-suspect growth | 35 |
| WX (writable+executable) page | 70 |

| Combined score | Escalated severity |
|---|---|
| ≥ 80 | critical |
| ≥ 50 | warning |
| below 50 | no escalation raised |

This is a heuristic weighting, not a calibrated statistical model — its
purpose is to make "several weak signals on one process at once" visibly
more significant than any one signal in isolation, which is closer to how a
real analyst would reason about it.

## Configuration

All thresholds live in `config.yaml`:
- `high_memory_percent` — flag a process using more than this % of total RAM
- `leak_growth_mb_per_min` — flag sustained RSS growth above this rate
- `poll_interval_seconds` — live monitor frequency
- `check_interval_seconds` — how often the known-vulnerability catalogue re-runs
- `signature_scan.check_interval_seconds` — how often the CVE signature catalogue re-runs
  (installed software/host config rarely changes, so this defaults to hourly, not every poll)

## Validation

Every detector in this project has been tested against a controlled,
known-condition scenario — not just claimed to work. See
[`test_scenarios/VALIDATION_RESULTS.md`](test_scenarios/VALIDATION_RESULTS.md)
for real captured runs, including PIDs, measured growth rates, and detected
permission patterns for the high-memory, leak, WX-page, and combined-risk
detectors. `test_scenarios/` also contains the scripts themselves so you
can reproduce these results yourself before presenting.

### Baseline false-positive validation (needs real elapsed time)

The detector-proof scenarios above confirm the logic works. They don't tell
you how noisy it is on ordinary, real usage — that needs actual elapsed
time, not a quick test.

**Start it:**
```bash
python main.py --silent
```
`--silent` logs every finding to `ram_guard.log` but skips all popup/email/
mobile alerts, so it runs quietly in the background. Use `nohup python
main.py --silent &` to keep it running after closing the terminal.

**Let it run** for a day or two of normal laptop use.

**Check results:**
```bash
python test_scenarios/summarize_baseline.py
```
Prints total findings, broken down by type and process — the real evidence
for whether current thresholds are too sensitive for this machine, instead
of a guess.

## OS support

Tested logic paths per platform (desktop popups, email, and push work
identically everywhere; the table below is about the *detection* layers):

| Check | Linux | Windows | macOS |
|---|---|---|---|
| Process memory usage / leak detection | ✅ Full | ✅ Full | ✅ Full |
| WX (writable+executable) page detection | ✅ Full (`/proc/<pid>/maps`) | ✅ Full (`VirtualQueryEx` region scan) | ⚠️ Degrades silently (no per-page perms without elevated entitlements) |
| Meltdown/Spectre exposure | ✅ Kernel sysfs read | ✅ Registry-based check | ⚠️ Manual (no public API) |
| DMA attack exposure | ✅ Manual pointer (IOMMU) | ✅ Registry-based check | ⚠️ Manual pointer |
| Rowhammer / cold-boot exposure | ⚠️ Manual pointer (all OSes — no OS exposes this) | ⚠️ Manual pointer | ⚠️ Manual pointer |

"Degrades silently" means the check simply returns no findings for that
specific sub-check rather than crashing — the rest of the tool keeps running
normally. "Manual pointer" means the tool tells you exactly what to check by
hand (e.g. run Microsoft's `Get-SpeculationControlSettings`) because no OS
exposes that data programmatically to any tool, ours included.

## Design notes & limitations

- The leak/anomaly detector is **heuristic**, tuned via config thresholds —
  it is meant to surface candidates for investigation, not provide forensic
  certainty.
- The WX-page check is best-effort. On Windows it walks the target process's
  address space with `VirtualQueryEx` looking for `PAGE_EXECUTE_READWRITE` /
  `PAGE_EXECUTE_WRITECOPY` regions — real coverage, not a stub. **But this
  indicator is inherently noisy on Windows**: JIT compilers in Chrome/Edge,
  Node.js, .NET, and Electron apps (including VS Code itself) legitimately
  allocate WX memory, so a large browser tab or IDE crossing the high-memory
  threshold will likely also trigger a `wx_pages` — and therefore
  `combined_risk` critical — finding purely from normal use. Validated live:
  on this machine, VS Code and Edge WebView2 both triggered "critical"
  combined-risk findings during ordinary use once the memory threshold was
  lowered for testing. Treat any WX finding as "worth a look", not
  "confirmed malicious" — this is exactly the kind of threshold-tuning
  candidate the baseline validation run (see below) exists to surface.
  macOS has no equivalent per-page permission API available without
  elevated entitlements and is not supported.
- Hardware-class checks (Rowhammer, cold-boot, DMA) cannot be fully verified
  from userspace software alone; the tool is explicit about this and routes
  those findings to "manual review" rather than asserting a false positive
  or negative.
- Desktop notifications use `plyer` and fall back to console output if no
  display/notification backend is available (e.g. headless server).

## Possible extensions
- Wire `detector/signature_scan.py`'s static catalogue to a live NVD/CVE
  feed for continuously updated matching, instead of the current
  hand-curated local list — trades offline/dependency-free operation for
  freshness.
- Add a Slack/Discord webhook notification channel alongside desktop
  popups, mobile push, and email.
- Persist findings to a time-series store for trend analysis over an
  internship/report period.
