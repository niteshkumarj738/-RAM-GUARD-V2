"""
known_vulnerabilities.py

A reference catalogue of well-documented RAM / memory-subsystem vulnerability
classes. This module does NOT contain exploit code. It provides:
  - metadata used for reporting / notification text
  - lightweight, non-invasive host checks that indicate *exposure risk*
    (e.g. mitigation flags, kernel version, CPU vendor) rather than
    attempting to actively trigger or exploit anything.

This is intentionally defensive: it tells the operator "your system may be
exposed to X because mitigation Y is absent", not "here is how to trigger X".

Scope, deliberately: every entry here has a REAL, software-checkable
mitigation signal on at least one platform -- either a kernel-exposed status
file (Linux) or a documented mitigation-override registry value (Windows).
Rowhammer and cold-boot attacks are real, well-known RAM vulnerabilities but
are NOT included here, on purpose: no operating system exposes DRAM
refresh-timing or RAM-remanence data to any software, on any platform, so a
"check" for them would always be a hardcoded guess rather than a real
result. They're documented as explicitly out of scope in the README instead
of being represented here as something this tool checks.
"""

import platform
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class VulnerabilityClass:
    vuln_id: str
    name: str
    category: str
    description: str
    reference: str
    check: Optional[Callable[[], "CheckResult"]] = field(default=None, repr=False)


@dataclass
class CheckResult:
    exposed: bool
    detail: str


def _linux_sysfs_vuln_check(filename: str) -> CheckResult:
    """Shared mechanism for every Linux speculative-execution check below:
    the kernel exposes a plain-text mitigation verdict per vulnerability
    under /sys/devices/system/cpu/vulnerabilities/. This is a real,
    definitive, kernel-authored answer -- not a heuristic."""
    try:
        out = subprocess.run(
            ["cat", f"/sys/devices/system/cpu/vulnerabilities/{filename}"],
            capture_output=True, text=True, timeout=3,
        )
        text = out.stdout.strip().lower()
        if "mitigation" in text or "not affected" in text:
            return CheckResult(exposed=False, detail=text or "Not affected.")
        elif text:
            return CheckResult(exposed=True, detail=f"Kernel reports: {text}")
        return CheckResult(exposed=True, detail="Vulnerability interface not readable; "
                                                  "kernel may predate this reporting mechanism.")
    except Exception as e:
        return CheckResult(exposed=True, detail=f"Could not query kernel interface: {e}")


def _windows_speculation_override_check(cve_label: str) -> CheckResult:
    """Shared mechanism for every Windows speculative-execution check below:
    Microsoft's FeatureSettingsOverride registry value (documented in
    KB4072698 and related advisories) governs the OS-level mitigation
    configuration for this entire vulnerability family (Meltdown, Spectre,
    MDS, L1TF all share this same override mechanism). Its presence means
    mitigation configuration has been explicitly set; its absence does NOT
    necessarily mean unmitigated -- many systems rely on default
    microcode/OS behaviour without ever setting an override. Microsoft's own
    Get-SpeculationControlSettings PowerShell script is the only fully
    definitive per-CVE verdict; this check is an honest proxy, not a
    replacement for it."""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
        )
        try:
            value, _ = winreg.QueryValueEx(key, "FeatureSettingsOverride")
            return CheckResult(
                exposed=False,
                detail=f"Mitigation override registry key present (value={value}); indicates "
                       f"OS-level {cve_label} mitigations have been configured. For a "
                       f"definitive per-CPU verdict, run Microsoft's "
                       f"Get-SpeculationControlSettings PowerShell script.",
            )
        except FileNotFoundError:
            return CheckResult(
                exposed=True,
                detail=f"No mitigation override registry value found. This does not "
                       f"necessarily mean unmitigated against {cve_label} (many systems rely "
                       f"on default microcode/OS behaviour) — run Microsoft's "
                       f"Get-SpeculationControlSettings script for a definitive check.",
            )
    except Exception as e:
        return CheckResult(
            exposed=True,
            detail=f"Could not read Windows registry ({e}); run Microsoft's "
                   f"Get-SpeculationControlSettings PowerShell script for a definitive check.",
        )


def _check_meltdown_spectre() -> CheckResult:
    """Meltdown/Spectre: speculative-execution side channels that can leak RAM contents."""
    system = platform.system()
    if system == "Linux":
        return _linux_sysfs_vuln_check("meltdown")
    elif system == "Windows":
        return _windows_speculation_override_check("Meltdown/Spectre")
    elif system == "Darwin":
        return CheckResult(
            exposed=True,
            detail="macOS does not expose per-vulnerability mitigation flags through a "
                   "standard userspace API. Apple ships CPU microcode/OS mitigations via "
                   "regular Software Update; verify the OS is fully up to date and check "
                   "Apple's security advisories for this specific CPU/T2/Apple Silicon model.",
        )
    return CheckResult(exposed=True, detail=f"Unsupported OS '{system}': manual review required.")


def _check_mds() -> CheckResult:
    """MDS (Microarchitectural Data Sampling) -- the ZombieLoad / RIDL / Fallout
    family (CVE-2018-12126, CVE-2018-12127, CVE-2018-12130, CVE-2019-11091).
    Leaks data across the CPU's internal buffers (store, fill, load ports)
    rather than through cache timing like Meltdown/Spectre -- a related but
    distinct 2019 disclosure, same speculative-execution root cause class."""
    system = platform.system()
    if system == "Linux":
        return _linux_sysfs_vuln_check("mds")
    elif system == "Windows":
        return _windows_speculation_override_check("MDS (ZombieLoad/RIDL/Fallout)")
    elif system == "Darwin":
        return CheckResult(
            exposed=True,
            detail="macOS does not expose per-vulnerability mitigation flags through a "
                   "standard userspace API. Verify the OS is fully up to date and check "
                   "Apple's security advisories for this CPU model.",
        )
    return CheckResult(exposed=True, detail=f"Unsupported OS '{system}': manual review required.")


def _check_l1tf() -> CheckResult:
    """L1TF / Foreshadow (CVE-2018-3615, CVE-2018-3620, CVE-2018-3646): a
    speculative-execution flaw that can read L1 cache contents across
    security boundaries, including from SGX enclaves and across VM
    hypervisor boundaries -- distinct from, but related to, Meltdown/Spectre."""
    system = platform.system()
    if system == "Linux":
        return _linux_sysfs_vuln_check("l1tf")
    elif system == "Windows":
        return _windows_speculation_override_check("L1TF/Foreshadow")
    elif system == "Darwin":
        return CheckResult(
            exposed=True,
            detail="macOS does not expose per-vulnerability mitigation flags through a "
                   "standard userspace API. Verify the OS is fully up to date and check "
                   "Apple's security advisories for this CPU model.",
        )
    return CheckResult(exposed=True, detail=f"Unsupported OS '{system}': manual review required.")


def _check_dma_attack() -> CheckResult:
    """DMA attack: malicious PCIe/Thunderbolt device reads RAM directly via DMA."""
    system = platform.system()
    if system == "Linux":
        return CheckResult(
            exposed=True,
            detail="Check IOMMU status (intel_iommu=on / amd_iommu=on) and Thunderbolt "
                   "security level manually; not auto-verifiable without elevated access.",
        )
    elif system == "Windows":
        try:
            import winreg
            # Kernel DMA Protection state is surfaced under this key on modern Windows
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\DeviceGuard",
            )
            try:
                value, _ = winreg.QueryValueEx(key, "EnableVirtualizationBasedSecurity")
                mitigated = bool(value)
                return CheckResult(
                    exposed=not mitigated,
                    detail=f"VirtualizationBasedSecurity registry flag = {value}. For a definitive "
                           f"verdict, check System Information → 'Kernel DMA Protection' field.",
                )
            except FileNotFoundError:
                return CheckResult(
                    exposed=True,
                    detail="No VBS registry flag found. Check System Information (msinfo32) → "
                           "'Kernel DMA Protection' field for the authoritative status.",
                )
        except Exception as e:
            return CheckResult(exposed=True, detail=f"Could not read registry ({e}); check "
                                                      f"msinfo32 → 'Kernel DMA Protection' manually.")
    elif system == "Darwin":
        return CheckResult(
            exposed=True,
            detail="Check System Settings → Privacy & Security → Thunderbolt access level "
                   "('Always require Approval' is the safest setting against DMA attacks).",
        )
    return CheckResult(exposed=True, detail="Manual review required for this OS.")


CATALOGUE = [
    VulnerabilityClass(
        vuln_id="RG-001",
        name="Meltdown / Spectre",
        category="Speculative Execution / RAM disclosure",
        description="Speculative execution side channels allow reading privileged "
                     "or cross-process memory contents.",
        reference="CVE-2017-5715, CVE-2017-5753, CVE-2017-5754",
        check=_check_meltdown_spectre,
    ),
    VulnerabilityClass(
        vuln_id="RG-002",
        name="MDS (ZombieLoad / RIDL / Fallout)",
        category="Speculative Execution / RAM disclosure",
        description="Microarchitectural Data Sampling: leaks data from the CPU's "
                     "internal store/fill/load buffers across security boundaries, "
                     "via speculative execution.",
        reference="CVE-2018-12126, CVE-2018-12127, CVE-2018-12130, CVE-2019-11091",
        check=_check_mds,
    ),
    VulnerabilityClass(
        vuln_id="RG-003",
        name="L1TF / Foreshadow",
        category="Speculative Execution / RAM disclosure",
        description="L1 Terminal Fault: speculative execution can read L1 cache "
                     "contents across security boundaries, including SGX enclaves "
                     "and virtual-machine hypervisor isolation.",
        reference="CVE-2018-3615, CVE-2018-3620, CVE-2018-3646",
        check=_check_l1tf,
    ),
    VulnerabilityClass(
        vuln_id="RG-004",
        name="DMA Attack",
        category="Physical / Peripheral RAM access",
        description="A malicious device on a DMA-capable bus (PCIe, Thunderbolt) "
                     "reads or writes system RAM directly, bypassing the OS.",
        reference="Thunderclap (2019); BadUSB-adjacent DMA class",
        check=_check_dma_attack,
    ),
]


def run_catalogue_scan():
    """Run all non-invasive checks and return a list of (VulnerabilityClass, CheckResult)."""
    results = []
    for vc in CATALOGUE:
        try:
            res = vc.check() if vc.check else CheckResult(False, "No automated check available.")
        except Exception as e:
            res = CheckResult(True, f"Check failed to run: {e}")
        results.append((vc, res))
    return results
