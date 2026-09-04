"""
dashboard.py

Streamlit dashboard for RAM-Guard. Gives a live, presentable view of:
  - current process memory findings
  - memory-corruption crash signatures (Windows Event Log)
  - CVE signature matches (installed software / host config)
  - known RAM-vulnerability-class exposure status

Run with: streamlit run dashboard.py
"""

import time
import pandas as pd
import streamlit as st

from detector.process_monitor import ProcessMemoryMonitor
from detector.known_vulnerabilities import run_catalogue_scan
from detector.crash_monitor import CrashCorruptionMonitor
from detector.signature_scan import run_signature_scan
import yaml

st.set_page_config(page_title="RAM-Guard", page_icon="🛡️", layout="wide")

with open("config.yaml") as f:
    cfg = yaml.safe_load(f)

if "monitor" not in st.session_state:
    st.session_state.monitor = ProcessMemoryMonitor(
        history_window=cfg["scan"]["history_window"],
        high_mem_pct=cfg["thresholds"]["high_memory_percent"],
        leak_mb_per_min=cfg["thresholds"]["leak_growth_mb_per_min"],
        min_samples=cfg["thresholds"]["min_samples_for_leak_check"],
        excluded_processes=cfg["thresholds"].get("excluded_processes", []),
    )

st.title("🛡️ RAM-Guard — RAM Vulnerability Detection & Alerting")
st.caption("Flags suspicious memory activity and known-attack indicators — "
           "not a claim of confirmed attacks. Multiple indicators on the same "
           "process together raise a combined risk score.")

col1, col2 = st.columns([2, 1])
with col2:
    if st.button("🔄 Run scan now", use_container_width=True):
        st.rerun()
    auto_refresh = st.checkbox("Auto-refresh every 5s", value=False)

# --- Live process findings -------------------------------------------------
st.subheader("Process Memory Findings")
findings = st.session_state.monitor.scan_once()

if findings:
    df = pd.DataFrame([{
        "PID": f.pid, "Process": f.name, "Type": f.kind,
        "Severity": f.severity, "Risk score": f.risk_score, "Detail": f.detail,
    } for f in findings])

    def _color(row):
        # Explicit dark text alongside the light background — Streamlit's
        # dark theme defaults to white cell text, which is unreadable on
        # these pastel highlight colors without overriding it too.
        c = {"critical": "background-color:#ffcccc;color:#4a0000",
             "warning": "background-color:#fff3cd;color:#4a3800",
             "info": "background-color:#d1ecf1;color:#003547"}.get(row["Severity"], "")
        return [c] * len(row)

    st.dataframe(df.style.apply(_color, axis=1), use_container_width=True, hide_index=True)
else:
    st.success("No process memory anomalies detected in this pass.")

# --- Memory-corruption crash signatures (Windows) ---------------------------
st.subheader("Memory Corruption Crashes (Windows Event Log)")
st.caption(
    "OS-confirmed application-level memory corruption — heap corruption, "
    "access violations, stack buffer overruns — read from the Windows "
    "Application Event Log, within the configured lookback window. This "
    "catches the moment a bug like this actually crashes a process; it "
    "does not scan source code for the bug itself."
)
crash_cfg = cfg.get("crash_monitor", {})
crash_findings = CrashCorruptionMonitor(
    lookback_minutes=crash_cfg.get("lookback_minutes", 10)
).scan_once()

if crash_findings:
    crash_df = pd.DataFrame([{
        "PID": f.pid, "Process": f.name, "Severity": f.severity, "Detail": f.detail,
    } for f in crash_findings])

    def _crash_color(row):
        return ["background-color:#ffcccc;color:#4a0000"] * len(row)

    st.dataframe(crash_df.style.apply(_crash_color, axis=1), use_container_width=True, hide_index=True)
else:
    st.success("No memory-corruption-class crashes in the lookback window.")

# --- CVE signature scan ------------------------------------------------------
st.subheader("CVE Signature Matches")
st.caption(
    "Installed software and host configuration checked against a static, "
    "offline catalogue of named, documented CVEs — no network calls. A "
    "match is a concrete fact about the host, not a heuristic, so every "
    "match is shown here regardless of severity."
)
sig_findings = run_signature_scan()

if sig_findings:
    sig_df = pd.DataFrame([{
        "CVE": f.cve_id, "Name": f.name, "Severity": f.severity, "Detail": f.detail,
    } for f in sig_findings])

    def _sig_color(row):
        c = {"critical": "background-color:#ffcccc;color:#4a0000",
             "warning": "background-color:#fff3cd;color:#4a3800",
             "info": "background-color:#d1ecf1;color:#003547"}.get(row["Severity"], "")
        return [c] * len(row)

    st.dataframe(sig_df.style.apply(_sig_color, axis=1), use_container_width=True, hide_index=True)
else:
    st.success("No known CVE signatures matched on this host.")

# --- Known vulnerability catalogue ------------------------------------------
st.subheader("Known RAM Vulnerability Class Exposure")
results = run_catalogue_scan()
cat_df = pd.DataFrame([{
    "ID": vc.vuln_id, "Name": vc.name, "Category": vc.category,
    "Status": "⚠️ Review needed" if res.exposed else "✅ Mitigated",
    "Detail": res.detail, "Reference": vc.reference,
} for vc, res in results])
st.dataframe(cat_df, use_container_width=True, hide_index=True)

st.caption(
    "Meltdown/Spectre, MDS, and L1TF read a real Windows mitigation-override registry "
    "value (or the Linux kernel's own per-vulnerability status file); DMA reads a real "
    "Kernel DMA Protection registry flag. None of these are guessed -- where a value is "
    "absent, that's reported honestly as \"can't fully confirm\" rather than assumed safe."
)

if auto_refresh:
    time.sleep(5)
    st.rerun()
