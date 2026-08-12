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


def _check_rowhammer() -> CheckResult:
    """Rowhammer: DRAM row disturbance leading to bit flips in adjacent rows.
    No OS exposes a definitive 'am I vulnerable' flag for this — it depends on
    DRAM refresh timing (TRR) and generation, which lives in firmware/DRAM
    datasheets, not the OS. All platforms are honestly flagged for manual
    firmware/BIOS review; the detail text just tells the operator where to look
    per OS."""
    system = platform.system()
    base = ("Cannot be conclusively verified from software alone; depends on "
            "DRAM refresh rate (TRR) and DDR generation.")
    if system == "Linux":
        return CheckResult(exposed=True, detail=f"{base} Check BIOS/UEFI DRAM timing settings "
                                                  f"and consider tools like TRRespass for testing.")
    elif system == "Windows":
        return CheckResult(exposed=True, detail=f"{base} Check BIOS/UEFI DRAM timing settings; "
                                                  f"Windows does not expose DRAM refresh info via any API.")
    elif system == "Darwin":
        return CheckResult(exposed=True, detail=f"{base} On Apple Silicon/T2 Macs, DRAM timing is "
                                                  f"fixed by Apple; check the specific model's published specs.")
    return CheckResult(exposed=True, detail=f"{base} Manual firmware/BIOS review required.")


def _check_meltdown_spectre() -> CheckResult:
    """Meltdown/Spectre: speculative-execution side channels that can leak RAM contents.
    Uses the real mitigation-status interface available on each OS rather than
    guessing; falls back to an honest 'manual check needed' only where the OS
    genuinely doesn't expose this."""
    system = platform.system()

    if system == "Linux":
        try:
            out = subprocess.run(
                ["cat", "/sys/devices/system/cpu/vulnerabilities/meltdown"],
                capture_output=True, text=True, timeout=3,
            )
            text = out.stdout.strip().lower()
            if "mitigation" in text:
                return CheckResult(exposed=False, detail=f"Mitigated: {text}")
            elif "not affected" in text:
                return CheckResult(exposed=False, detail=text)
            elif text:
                return CheckResult(exposed=True, detail=f"Kernel reports: {text}")
            else:
                return CheckResult(exposed=True, detail="Vulnerability interface not readable; "
                                                          "kernel may predate this reporting mechanism.")
        except Exception as e:
            return CheckResult(exposed=True, detail=f"Could not query kernel interface: {e}")

    elif system == "Windows":
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
                    detail=f"Mitigation override registry key present (value={value}); "
                           f"indicates OS-level Meltdown/Spectre mitigations have been configured. "
                           f"For a definitive per-CPU verdict, run Microsoft's "
                           f"Get-SpeculationControlSettings PowerShell script.",
                )
            except FileNotFoundError:
                return CheckResult(
                    exposed=True,
                    detail="No mitigation override registry value found. This does not "
                           "necessarily mean unmitigated (many systems rely on default "
                           "microcode/OS behaviour) — run Microsoft's "
                           "Get-SpeculationControlSettings script for a definitive check.",
                )
        except Exception as e:
            return CheckResult(
                exposed=True,
                detail=f"Could not read Windows registry ({e}); run Microsoft's "
                       f"Get-SpeculationControlSettings PowerShell script for a definitive check.",
            )

    elif system == "Darwin":
        return CheckResult(
            exposed=True,
            detail="macOS does not expose per-vulnerability mitigation flags through a "
                   "standard userspace API. Apple ships CPU microcode/OS mitigations via "
                   "regular Software Update; verify the OS is fully up to date and check "
                   "Apple's security advisories for this specific CPU/T2/Apple Silicon model.",
        )

    return CheckResult(exposed=True, detail=f"Unsupported OS '{system}': manual review required.")


def _check_cold_boot() -> CheckResult:
    """Cold-boot attack: RAM remanence allows key/data recovery after power-off."""
    return CheckResult(
        exposed=True,
        detail="Software cannot detect this directly. Mitigation depends on "
               "full-disk encryption + memory scrambling/TRESOR-style key handling. "
               "Flagged for manual policy check.",
    )


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
        name="Rowhammer",
        category="Hardware / DRAM",
        description="Repeated rapid access to a DRAM row can induce bit flips in "
                     "physically adjacent rows, potentially corrupting data or "
                     "escalating privileges.",
        reference="CVE-2015-0565 class; Kim et al. 2014",
        check=_check_rowhammer,
    ),
    VulnerabilityClass(
        vuln_id="RG-002",
        name="Meltdown / Spectre",
        category="Speculative Execution / RAM disclosure",
        description="Speculative execution side channels allow reading privileged "
                     "or cross-process memory contents.",
        reference="CVE-2017-5715, CVE-2017-5753, CVE-2017-5754",
        check=_check_meltdown_spectre,
    ),
    VulnerabilityClass(
        vuln_id="RG-003",
        name="Cold Boot Attack",
        category="Physical / RAM remanence",
        description="Data persists briefly in RAM after power loss, allowing "
                     "extraction of encryption keys or sensitive data via a "
                     "quick reboot or chip transplant.",
        reference="Halderman et al. 2008",
        check=_check_cold_boot,
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
