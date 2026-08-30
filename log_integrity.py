"""
log_integrity.py

Tamper-evidence for ram_guard.log: a SHA-256 hash chain, one entry per log
line, kept in a sidecar file (ram_guard.log.hashes). Each entry is
hash_n = sha256(hash_{n-1} + line_n), so modifying, deleting, or reordering
any earlier line invalidates every hash computed after it, not just that
one line -- the same construction used for tamper-evident audit logs
generally. The log file itself stays a normal, human-readable text file;
this only adds an independent verification trail alongside it.

This detects *tampering after the fact*, via `python log_integrity.py
--verify`. It does not prevent an attacker with write access to both
files from tampering with the log AND rebuilding a matching hash chain --
no local file-based scheme can fully prevent that. What it does catch is
casual/incomplete tampering (editing the log without touching the hash
file, or vice versa), and it's the standard bar for this class of local
tool -- full protection would need a remote/append-only log destination.

Usage (as a library):
    handler = HashChainHandler(hash_path)
    logging.getLogger().addHandler(handler)

Usage (CLI verification):
    python log_integrity.py --verify
    python log_integrity.py --verify --log ram_guard.log --hashes ram_guard.log.hashes
"""

import argparse
import hashlib
import logging
import sys
from pathlib import Path

GENESIS = "0" * 64


class HashChainHandler(logging.Handler):
    """Logging handler that appends one hash-chain entry per formatted log
    record to a sidecar file. Add alongside the normal FileHandler -- it
    doesn't write to the log file itself, only to the hash-chain file, so
    it works with whatever formatter the rest of the logging setup uses."""

    def __init__(self, hash_path):
        super().__init__()
        self.hash_path = Path(hash_path)
        self._prev_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        if self.hash_path.exists():
            lines = self.hash_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            if lines:
                return lines[-1]
        return GENESIS

    def emit(self, record):
        try:
            msg = self.format(record)
            new_hash = hashlib.sha256((self._prev_hash + msg).encode("utf-8")).hexdigest()
            with open(self.hash_path, "a", encoding="utf-8") as f:
                f.write(new_hash + "\n")
            self._prev_hash = new_hash
        except Exception:
            self.handleError(record)


def verify(log_path: Path, hash_path: Path):
    """Returns (ok, message). ok is None if there's nothing to verify yet."""
    if not log_path.exists() or not hash_path.exists():
        return None, "Log or hash-chain file missing -- nothing to verify yet."

    log_lines = log_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    hash_lines = hash_path.read_text(encoding="utf-8", errors="ignore").splitlines()

    if len(log_lines) != len(hash_lines):
        return False, (f"Line count mismatch: {len(log_lines)} log lines vs "
                        f"{len(hash_lines)} hash-chain entries -- the log was likely "
                        f"truncated, edited, or appended to outside RAM-Guard.")

    prev = GENESIS
    for i, (line, stored_hash) in enumerate(zip(log_lines, hash_lines), start=1):
        expected = hashlib.sha256((prev + line).encode("utf-8")).hexdigest()
        if expected != stored_hash:
            return False, f"Hash chain broken at log line {i} -- content modified since it was written."
        prev = expected

    return True, f"Verified: {len(log_lines)} log lines, hash chain intact."


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="Verify RAM-Guard log integrity via its hash chain")
    parser.add_argument("--verify", action="store_true", help="Run verification (the only supported mode)")
    parser.add_argument("--log", default=str(Path(__file__).parent / "ram_guard.log"))
    parser.add_argument("--hashes", default=str(Path(__file__).parent / "ram_guard.log.hashes"))
    args = parser.parse_args()

    ok, message = verify(Path(args.log), Path(args.hashes))
    print(message)
    if ok is False:
        sys.exit(1)


if __name__ == "__main__":
    main()
