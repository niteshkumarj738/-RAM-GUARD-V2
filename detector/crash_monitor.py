"""
crash_monitor.py

Watches the Windows Application Event Log for process crashes whose
exception code is a direct, OS-confirmed signature of memory corruption:
heap corruption (double-free / heap buffer overflow), access violations
(use-after-free / buffer overflow gone wrong), and stack buffer overruns
(/GS canary violations). This catches the moment such a bug actually
corrupts memory badly enough to crash a process — Windows' own heap
manager and exception system are the ones flagging it, not a guess.

This does NOT find these bugs in source code before they're triggered;
that requires static analysis or instrumented builds (a different tool
category: Coverity, AddressSanitizer, Valgrind). This is a black-box,
after-the-fact signal, consistent with the rest of RAM-Guard's approach.

Windows only. On other platforms, scan_once() returns an empty list.
"""

import json
import platform
import re
import subprocess
from dataclasses import dataclass
from typing import List, Set

_IS_WINDOWS = platform.system() == "Windows"

# Windows exception codes that specifically indicate memory corruption,
# not just any crash (e.g. this deliberately excludes divide-by-zero and
# other non-memory-safety exception codes).
_EXCEPTION_MEANINGS = {
    "0xc0000005": "Access violation — often a use-after-free, buffer "
                  "overflow, or null-pointer dereference gone wrong.",
    "0xc0000374": "Heap corruption detected by Windows' own heap manager "
                  "— a strong, direct signature of a double-free or heap "
                  "buffer overflow.",
    "0xc0000409": "Stack buffer overrun — the compiler's /GS stack canary "
                  "caught a stack-based buffer overflow.",
}

# Standard Windows "Application Error" (Event ID 1000) message format.
# Name capture excludes ',' since the log line is "name.exe, version: ...".
_FAULT_RE = re.compile(
    r"Faulting application name:\s*(?P<name>[^,\s]+).*?"
    r"Exception code:\s*(?P<code>0x[0-9a-fA-F]+).*?"
    r"Faulting process id:\s*0x(?P<pid>[0-9a-fA-F]+)",
    re.IGNORECASE | re.DOTALL,
)


@dataclass
class CrashFinding:
    pid: int
    name: str
    kind: str
    detail: str
    severity: str = "critical"
    risk_score: int = 90  # OS-confirmed corruption; higher than any single heuristic signal


class CrashCorruptionMonitor:
    """Polls the Windows Application Event Log for Event ID 1000
    ("Application Error") entries with a memory-corruption exception
    code, reporting only ones not already seen this run."""

    def __init__(self, lookback_minutes: int = 10):
        self.lookback_minutes = lookback_minutes
        self._seen_record_ids: Set[int] = set()

    def scan_once(self) -> List[CrashFinding]:
        if not _IS_WINDOWS:
            return []

        ps_cmd = (
            f"Get-WinEvent -FilterHashtable @{{LogName='Application';Id=1000;"
            f"StartTime=(Get-Date).AddMinutes(-{self.lookback_minutes})}} "
            f"-ErrorAction SilentlyContinue | "
            f"Select-Object RecordId, Message | ConvertTo-Json -Compress"
        )
        try:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=15,
            )
        except Exception:
            return []

        raw = out.stdout.strip()
        if not raw:
            return []

        try:
            events = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return []
        if isinstance(events, dict):
            events = [events]

        findings: List[CrashFinding] = []
        for ev in events:
            record_id = ev.get("RecordId")
            message = ev.get("Message", "") or ""
            if record_id is None or record_id in self._seen_record_ids:
                continue
            self._seen_record_ids.add(record_id)

            m = _FAULT_RE.search(message)
            if not m:
                continue
            code = m.group("code").lower()
            meaning = _EXCEPTION_MEANINGS.get(code)
            if not meaning:
                continue  # a real crash, but not a memory-corruption-class exception code

            name = m.group("name")
            pid = int(m.group("pid"), 16)
            findings.append(CrashFinding(
                pid=pid, name=name, kind="memory_corruption_crash",
                detail=f"{name} (PID {pid}) crashed with exception {code} — {meaning}",
            ))
        return findings
