"""
process_monitor.py

Watches running processes for RAM-usage patterns that commonly correlate with:
  - memory leaks (sustained, near-linear RSS growth)
  - abnormal single-process RAM hogging
  - (best-effort) writable+executable memory pages, a classic indicator of
    in-memory code injection / exploited buffer overflows. Linux and Windows
    are both supported; other platforms don't expose this without elevated
    entitlements and are skipped.

This is heuristic and host-agnostic; it flags candidates for investigation,
it does not claim certainty. In particular, WX pages are also produced by
legitimate JIT compilers (browsers, Node.js, .NET, Electron apps) — this
detector deliberately does not try to tell "legitimate JIT" from "exploit"
apart, since that distinction needs more context than a memory scan alone
can provide. Treat a WX finding as "worth a look", not "confirmed malicious".
"""

import ctypes
import platform
import time
import psutil
from collections import defaultdict, deque
from ctypes import wintypes
from dataclasses import dataclass
from typing import Deque, Dict, List, Tuple

_IS_WINDOWS = platform.system() == "Windows"

if _IS_WINDOWS:
    _PAGE_EXECUTE_READWRITE = 0x40
    _PAGE_EXECUTE_WRITECOPY = 0x80
    _WX_PROTECT_FLAGS = {_PAGE_EXECUTE_READWRITE, _PAGE_EXECUTE_WRITECOPY}
    _MEM_COMMIT = 0x1000
    _PROCESS_QUERY_INFORMATION = 0x0400
    _PROCESS_VM_READ = 0x0010
    # Practical ceiling on user-mode address space (x64); stops the scan
    # loop from running away if VirtualQueryEx behaves unexpectedly.
    _USER_SPACE_CEILING = 0x7FFFFFFF0000

    class _MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]

    def _scan_wx_regions_windows(pid: int) -> List[Tuple[int, int]]:
        """Walk a process's address space with VirtualQueryEx and return
        (base_address, region_size) for every committed region that is
        simultaneously writable and executable. Only needs
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ — no write/exec access
        to the target is required, this never touches the region's contents."""
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(_PROCESS_QUERY_INFORMATION | _PROCESS_VM_READ, False, pid)
        if not handle:
            return []
        regions: List[Tuple[int, int]] = []
        try:
            address = 0
            mbi = _MEMORY_BASIC_INFORMATION()
            while address < _USER_SPACE_CEILING:
                ok = kernel32.VirtualQueryEx(handle, ctypes.c_void_p(address),
                                              ctypes.byref(mbi), ctypes.sizeof(mbi))
                if not ok:
                    break
                if mbi.State == _MEM_COMMIT and mbi.Protect in _WX_PROTECT_FLAGS:
                    regions.append((mbi.BaseAddress or 0, mbi.RegionSize))
                if mbi.RegionSize == 0:
                    break
                address += mbi.RegionSize
        finally:
            kernel32.CloseHandle(handle)
        return regions


@dataclass
class Finding:
    pid: int
    name: str
    kind: str          # "high_memory" | "leak_suspect" | "wx_pages" | "combined_risk"
    detail: str
    severity: str       # "info" | "warning" | "critical"
    risk_score: int = 0  # contribution to this process's combined risk score


# Base risk points per indicator type. These are heuristic weights, not a
# calibrated model — they exist so that MULTIPLE weak signals on the SAME
# process can escalate to a stronger alert than any single signal alone,
# without ever suppressing the individual signal's own notification.
RISK_WEIGHTS = {
    "high_memory": 25,
    "leak_suspect": 35,
    "wx_pages": 70,   # already strong on its own
}

# Combined-score thresholds -> escalated severity for the extra "combined_risk" finding
COMBINED_THRESHOLDS = [
    (80, "critical"),
    (50, "warning"),
]


class ProcessMemoryMonitor:
    def __init__(self, history_window: int, high_mem_pct: float,
                 leak_mb_per_min: float, min_samples: int):
        self.history_window = history_window
        self.high_mem_pct = high_mem_pct
        self.leak_mb_per_min = leak_mb_per_min
        self.min_samples = min_samples
        self._history: Dict[int, Deque[Tuple[float, float]]] = defaultdict(
            lambda: deque(maxlen=self.history_window)
        )  # pid -> deque[(timestamp, rss_mb)]

    def _check_wx_pages(self, proc: psutil.Process) -> List[Finding]:
        """Best-effort: flag memory regions that are simultaneously writable
        and executable — the classic fingerprint of in-memory code injection,
        regardless of which specific exploit produced it. Supported on Linux
        (via /proc/<pid>/maps perms) and Windows (via VirtualQueryEx region
        protection flags); other platforms return nothing rather than guess.

        Note: legitimate JIT compilers (browser JS engines, Node.js, .NET,
        Electron apps) also create WX regions as normal behaviour, so this is
        flagged as a candidate for review, not a confirmed exploit."""
        findings: List[Finding] = []

        if _IS_WINDOWS:
            try:
                regions = _scan_wx_regions_windows(proc.pid)
            except Exception:
                return findings
            for base, size in regions:
                findings.append(Finding(
                    pid=proc.pid, name=proc.name(), kind="wx_pages",
                    detail=f"Writable+executable memory region at 0x{base:012X} "
                           f"({size} bytes) — in-memory code injection pattern "
                           f"(also produced by legitimate JIT compilers; review needed).",
                    severity="warning",
                ))
            return findings

        try:
            maps = proc.memory_maps(grouped=False)
        except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError, NotImplementedError):
            return findings

        for m in maps:
            perms = getattr(m, "perms", None)
            if perms and "w" in perms and "x" in perms:
                findings.append(Finding(
                    pid=proc.pid, name=proc.name(), kind="wx_pages",
                    detail=f"Writable+executable mapping at {getattr(m, 'path', 'anon')} "
                           f"(perms={perms})",
                    severity="critical",
                ))
        return findings

    def scan_once(self) -> List[Finding]:
        findings: List[Finding] = []
        total_ram_mb = psutil.virtual_memory().total / (1024 * 1024)
        now = time.time()

        for proc in psutil.process_iter(["pid", "name", "memory_info", "memory_percent"]):
            try:
                info = proc.info
                rss_mb = info["memory_info"].rss / (1024 * 1024) if info["memory_info"] else 0
                mem_pct = info["memory_percent"] or 0.0
                pid, name = info["pid"], info["name"] or "unknown"

                # 1. High single-process memory usage
                if mem_pct >= self.high_mem_pct:
                    findings.append(Finding(
                        pid=pid, name=name, kind="high_memory",
                        detail=f"{mem_pct:.1f}% of system RAM ({rss_mb:.0f} MB)",
                        severity="warning",
                        risk_score=RISK_WEIGHTS["high_memory"],
                    ))

                # 2. Leak-suspect growth tracking
                hist = self._history[pid]
                hist.append((now, rss_mb))
                if len(hist) >= self.min_samples:
                    t0, m0 = hist[0]
                    t1, m1 = hist[-1]
                    minutes = max((t1 - t0) / 60.0, 1e-6)
                    growth_rate = (m1 - m0) / minutes

                    # A real leak grows steadily; ordinary apps (browsers,
                    # IDEs, the OS memory compressor) spike and release
                    # memory constantly and can hit the same average rate
                    # comparing only the first and last sample. Require most
                    # of the window to be trending upward too, not just the
                    # endpoints. Tuned against a real 7h baseline capture on
                    # this machine, which showed Chrome/VS Code/MemCompression
                    # firing ~3400 false positives under the rate check alone.
                    samples = list(hist)
                    rising_steps = sum(
                        1 for (_, a), (_, b) in zip(samples, samples[1:])
                        if b >= a - 1.0  # 1 MB tolerance for sampling noise
                    )
                    consistency = rising_steps / (len(samples) - 1)

                    if growth_rate >= self.leak_mb_per_min and consistency >= 0.75:
                        findings.append(Finding(
                            pid=pid, name=name, kind="leak_suspect",
                            detail=f"RSS growing ~{growth_rate:.1f} MB/min over "
                                   f"{len(hist)} samples ({m0:.0f}→{m1:.0f} MB), "
                                   f"{consistency:.0%} consistently upward",
                            severity="warning",
                            risk_score=RISK_WEIGHTS["leak_suspect"],
                        ))

                # 3. WX page scan (lighter weight, only on flagged/likely processes to save cost)
                if mem_pct >= self.high_mem_pct:
                    for f in self._check_wx_pages(proc):
                        f.risk_score = RISK_WEIGHTS["wx_pages"]
                        findings.append(f)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        findings.extend(self._compute_combined_risk(findings))
        return findings

    def _compute_combined_risk(self, findings: List[Finding]) -> List[Finding]:
        """Every individual finding above already notifies on its own —
        this never suppresses that. This only ADDS an extra finding when
        two or more DIFFERENT indicators fire on the SAME process in the
        SAME pass, since that combination is more meaningful than any one
        signal alone (e.g. high memory + fast growth together is a much
        stronger signal than either fact by itself)."""
        by_pid: Dict[int, List[Finding]] = defaultdict(list)
        for f in findings:
            by_pid[f.pid].append(f)

        escalations: List[Finding] = []
        for pid, flist in by_pid.items():
            distinct_kinds = {f.kind for f in flist}
            if len(distinct_kinds) < 2:
                continue  # single indicator — already notified individually, nothing to add

            total_score = sum(f.risk_score for f in flist)
            severity = "info"
            for threshold, sev in COMBINED_THRESHOLDS:
                if total_score >= threshold:
                    severity = sev
                    break

            escalations.append(Finding(
                pid=pid, name=flist[0].name, kind="combined_risk",
                detail=f"{len(distinct_kinds)} indicators together "
                       f"({', '.join(sorted(distinct_kinds))}) — combined risk score {total_score}",
                severity=severity,
                risk_score=total_score,
            ))
        return escalations
