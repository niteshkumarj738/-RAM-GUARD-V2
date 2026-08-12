"""
wx_page_demo.py

Deliberately maps a memory page as writable+executable in its OWN process,
to validate that RAM-Guard's WX-page detector correctly flags this
well-known exploitation indicator.

IMPORTANT: this contains no shellcode and does not execute the mapped
region. It only creates the permission pattern (RWX) that real exploits
rely on, so the detector has something legitimate to catch. This is a
standard technique for testing security-monitoring tools (a "canary"
allocation), not an attack.

Linux only (uses the mmap module's PROT_EXEC flag).

Usage:
    python wx_page_demo.py --hold-seconds 60
"""

import argparse
import mmap
import sys
import time
import os

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def make_wx_page(hold_seconds: int):
    if os.name != "posix":
        print("[wx_page_demo] This demo requires a POSIX (Linux) system for mmap PROT_EXEC.")
        return

    size = mmap.PAGESIZE
    # PROT_READ | PROT_WRITE | PROT_EXEC — the exact pattern the detector looks for.
    # No code is ever written into this page or executed.
    mm = mmap.mmap(-1, size, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
    print(f"[wx_page_demo] PID={os.getpid()} created a writable+executable page "
          f"({size} bytes). Holding for {hold_seconds}s — point RAM-Guard at this PID now.")
    time.sleep(hold_seconds)
    mm.close()
    print("[wx_page_demo] Done, page released.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Controlled WX-page allocation for validating RAM-Guard")
    parser.add_argument("--hold-seconds", type=int, default=60)
    args = parser.parse_args()
    make_wx_page(args.hold_seconds)
