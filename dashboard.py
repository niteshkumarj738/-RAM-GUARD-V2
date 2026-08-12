"""
dashboard.py

Streamlit dashboard for RAM-Guard. Gives a live, presentable view of:
  - current process memory findings
  - known RAM-vulnerability-class exposure status

Run with: streamlit run dashboard.py
"""

import time
import pandas as pd
import streamlit as st

from detector.process_monitor import ProcessMemoryMonitor
from detector.known_vulnerabilities import run_catalogue_scan
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
        c = {"critical": "background-color:#ffcccc",
             "warning": "background-color:#fff3cd",
             "info": "background-color:#d1ecf1"}.get(row["Severity"], "")
        return [c] * len(row)

    st.dataframe(df.style.apply(_color, axis=1), use_container_width=True, hide_index=True)
else:
    st.success("No process memory anomalies detected in this pass.")

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
    "Note: hardware-class checks (Rowhammer, cold-boot, DMA) cannot be fully verified "
    "in software alone and are flagged for manual firmware/BIOS/IOMMU review where "
    "conclusive detection isn't possible from userspace."
)

if auto_refresh:
    time.sleep(5)
    st.rerun()
