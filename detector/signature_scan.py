"""
signature_scan.py

Static, offline signature-based vulnerability detection: matches installed
software and known-risky host configuration against a local catalogue of
real, documented, RAM/memory-related CVEs (buffer overflows, heap
corruption, use-after-free, memory-disclosure bugs) -- not a live feed.
Nothing here is fetched over the network; the catalogue below is the
entire signature source, kept in this file so it's auditable at a glance.

Two signature types:
  - "software_version": installed program (read from the Windows Uninstall
    registry, no elevated privileges needed) at or below a known-vulnerable
    version.
  - "host_config": a specific, checkable host setting that is the
    documented defense-in-depth mitigation for a named CVE (e.g. disabling
    SMBv1 for EternalBlue-class attacks), independent of patch level.

Every match here is a concrete signature hit, not a heuristic -- unlike
the process monitor's high-memory/leak-growth findings, EVERY signature
match is intended to notify (see main.py's run_signature_scan), not just
critical ones. That's a deliberate difference from the rest of RAM-Guard:
a version match against a named CVE is a fact about the host, not a
probabilistic behavioural signal.

Windows-focused (registry-based); returns no software_version findings on
other platforms since there's no equivalent non-invasive inventory API
without extra dependencies. host_config checks are individually
platform-guarded and degrade silently elsewhere, same convention as
known_vulnerabilities.py.
"""

import platform
import re
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

_IS_WINDOWS = platform.system() == "Windows"

if _IS_WINDOWS:
    import winreg


@dataclass
class SoftwareSignature:
    sig_id: str
    cve_id: str
    name: str
    category: str
    product_match: str       # case-insensitive substring matched against installed DisplayName
    fixed_version: str       # installed version strictly below this is vulnerable
    severity: str            # "critical" | "warning" | "info"
    description: str
    reference: str


@dataclass
class ConfigSignature:
    sig_id: str
    cve_id: str
    name: str
    category: str
    severity: str
    check: Callable[[], Optional[str]]  # returns detail string if exposed, else None
    reference: str


@dataclass
class SignatureFinding:
    sig_id: str
    cve_id: str
    name: str
    kind: str = "signature_match"
    severity: str = "warning"
    detail: str = ""
    risk_score: int = 60


def _version_tuple(v: str) -> Tuple[int, ...]:
    """Parse a dotted version string into a comparable int tuple. Non-numeric
    trailing labels (e.g. '5.70b3', '3.0.7-rc1') are truncated at the first
    non-numeric component rather than raising, so a comparison never crashes
    the scan -- an unparsable version is simply skipped by the caller."""
    parts = re.findall(r"\d+", v)
    return tuple(int(p) for p in parts) if parts else tuple()


def _version_below(installed: str, fixed: str) -> Optional[bool]:
    a, b = _version_tuple(installed), _version_tuple(fixed)
    if not a or not b:
        return None  # unparsable -- don't guess
    return a < b


# --- Windows installed-software inventory (Uninstall registry keys) -------

_UNINSTALL_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall") if _IS_WINDOWS else None,
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall") if _IS_WINDOWS else None,
]


def _installed_software() -> List[Tuple[str, str]]:
    """Read (DisplayName, DisplayVersion) pairs from the standard Windows
    Uninstall registry locations. No elevated privileges required -- this
    is the same data Control Panel > Programs reads from."""
    if not _IS_WINDOWS:
        return []
    results: List[Tuple[str, str]] = []
    for hive, path in [k for k in _UNINSTALL_KEYS if k]:
        try:
            key = winreg.OpenKey(hive, path)
        except OSError:
            continue
        try:
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                except OSError:
                    break
                i += 1
                try:
                    subkey = winreg.OpenKey(key, subkey_name)
                    name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                    version, _ = winreg.QueryValueEx(subkey, "DisplayVersion")
                    results.append((str(name), str(version)))
                except OSError:
                    continue
        finally:
            winreg.CloseKey(key)
    return results


# --- host_config checks: documented mitigations for specific named CVEs ---

def _check_smbv1_enabled() -> Optional[str]:
    """EternalBlue (CVE-2017-0144 / MS17-010) exploited a buffer overflow in
    SMBv1. Modern patched systems aren't vulnerable to the original exploit,
    but Microsoft's own long-standing guidance is to disable SMBv1 entirely
    as defense-in-depth, since it carries no benefit an actively maintained
    protocol version doesn't already provide. Flags if the SMB1 server
    feature registry value indicates it's still enabled (default state
    varies by Windows edition/version)."""
    if not _IS_WINDOWS:
        return None
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        )
        try:
            value, _ = winreg.QueryValueEx(key, "SMB1")
            if value == 1:
                return ("SMB1 registry value = 1 (enabled). This is the protocol version "
                        "targeted by EternalBlue/MS17-010. Patched systems aren't vulnerable "
                        "to the original exploit, but Microsoft recommends disabling SMBv1 "
                        "entirely: Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol.")
        except FileNotFoundError:
            return None  # value absent -- OS default applies, not a positive finding either way
    except Exception:
        return None
    return None


def _check_smbv3_compression() -> Optional[str]:
    """CVE-2020-0796 ("SMBGhost") is a wormable heap-based buffer overflow in
    the SMBv3 compression handler (Windows 10 1903/1909). Microsoft's
    published interim mitigation, for systems that can't immediately patch,
    is disabling SMBv3 compression via registry (ADV200005 / KB4551762).
    Flags hosts where that mitigation registry value isn't set to disabled --
    same defense-in-depth convention as the SMBv1 and RDP/NLA checks above:
    patched systems aren't vulnerable to the original exploit either way,
    this just reports whether the documented interim mitigation is active."""
    if not _IS_WINDOWS:
        return None
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
        )
        try:
            value, _ = winreg.QueryValueEx(key, "DisableCompression")
        except FileNotFoundError:
            value = 0  # absent -- OS default is compression enabled, i.e. not mitigated
        if value == 1:
            return None  # mitigation active
        return ("SMBv3 compression mitigation (DisableCompression) not set. This is "
                "Microsoft's documented interim mitigation for CVE-2020-0796 "
                "(\"SMBGhost\"), a wormable heap buffer overflow in SMBv3 compression "
                "handling, for systems that haven't applied the March 2020 patch: "
                "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\"
                "LanmanServer\\Parameters' -Name 'DisableCompression' -Value 1 -Force.")
    except Exception:
        return None


def _check_rdp_without_nla() -> Optional[str]:
    """BlueKeep (CVE-2019-0708) was a pre-authentication use-after-free in
    Remote Desktop Services. Network Level Authentication (NLA) forces
    credential checks before the vulnerable pre-auth code path is reached,
    and was Microsoft's own recommended stop-gap mitigation during the
    BlueKeep response. Flags RDP-enabled hosts that don't have NLA on."""
    if not _IS_WINDOWS:
        return None
    try:
        ts_key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Terminal Server",
        )
        try:
            deny, _ = winreg.QueryValueEx(ts_key, "fDenyTSConnections")
        except FileNotFoundError:
            return None
        if deny != 0:
            return None  # RDP not enabled -- nothing to flag

        try:
            rdp_tcp_key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            )
            nla, _ = winreg.QueryValueEx(rdp_tcp_key, "UserAuthentication")
        except FileNotFoundError:
            nla = 0
        if nla == 0:
            return ("Remote Desktop is enabled without Network Level Authentication. "
                    "NLA is Microsoft's documented defense-in-depth mitigation for the "
                    "BlueKeep-class pre-auth RCE (CVE-2019-0708) in Remote Desktop "
                    "Services. Patched systems aren't vulnerable to the original exploit, "
                    "but enabling NLA closes the pre-auth attack surface regardless of "
                    "patch level: System Properties > Remote > 'Allow connections only "
                    "from computers running Remote Desktop with NLA'.")
    except Exception:
        return None
    return None


SOFTWARE_SIGNATURES: List[SoftwareSignature] = [
    SoftwareSignature(
        sig_id="SIG-001",
        cve_id="CVE-2018-20250",
        name="WinRAR ACE Extraction Path Traversal / Code Execution",
        category="Memory Corruption / Archive Extraction",
        product_match="winrar",
        fixed_version="5.70",
        severity="critical",
        description="The bundled UNACEV2.DLL mishandled absolute paths during ACE "
                    "archive extraction, allowing a crafted archive to write outside "
                    "the extraction directory and achieve code execution. Fixed by "
                    "removing ACE format support entirely in 5.70.",
        reference="CVE-2018-20250 (Check Point Research, 2019)",
    ),
    SoftwareSignature(
        sig_id="SIG-002",
        cve_id="CVE-2016-2334 / CVE-2016-2335",
        name="7-Zip Heap-Based Buffer Overflow (UDF / HFS parsing)",
        category="Heap Memory Corruption",
        product_match="7-zip",
        fixed_version="16.00",
        severity="warning",
        description="Heap-based buffer overflow when parsing crafted UDF or HFS+ "
                    "archive volume headers, reachable simply by browsing a malicious "
                    "archive's contents.",
        reference="CVE-2016-2334, CVE-2016-2335 (Cisco Talos, 2016)",
    ),
    SoftwareSignature(
        sig_id="SIG-003",
        cve_id="CVE-2019-13615",
        name="VLC Heap Buffer Over-Read (WAV demuxer)",
        category="Memory Disclosure / Denial of Service",
        product_match="vlc media player",
        fixed_version="3.0.7",
        severity="warning",
        description="Heap-based buffer over-read in the WAV file demuxer when "
                    "opening a crafted .wav file, able to crash the player or leak "
                    "adjacent heap memory contents.",
        reference="CVE-2019-13615 (VideoLAN, 2019)",
    ),
    SoftwareSignature(
        sig_id="SIG-004",
        cve_id="CVE-2018-4878",
        name="Adobe Flash Player Use-After-Free",
        category="Use-After-Free / Remote Code Execution",
        product_match="adobe flash player",
        fixed_version="28.0.0.137",
        severity="critical",
        description="Use-after-free in the ActionScript 2 NetStream class, exploited "
                    "in the wild via crafted Flash content before a public fix existed. "
                    "Included for legacy/regulated-environment coverage: Flash Player "
                    "reached end-of-life in Jan 2021 and was force-removed on most "
                    "consumer systems, but older or air-gapped machines can still carry it.",
        reference="CVE-2018-4878 (KISA/Adobe APSA18-01, 2018)",
    ),
    SoftwareSignature(
        sig_id="SIG-005",
        cve_id="CVE-2021-36367",
        name="PuTTY Integer Overflow -> Heap Buffer Overflow (terminal emulation)",
        category="Heap Memory Corruption",
        product_match="putty",
        fixed_version="0.75",
        severity="warning",
        description="An integer overflow in PuTTY's terminal-emulation handling of "
                    "certain crafted escape sequences could lead to a heap-based buffer "
                    "overflow, triggerable by a malicious server or MITM the user connects to.",
        reference="CVE-2021-36367 (PuTTY vulnerability list, 2021)",
    ),
]

CONFIG_SIGNATURES: List[ConfigSignature] = [
    ConfigSignature(
        sig_id="SIG-101",
        cve_id="CVE-2017-0144",
        name="SMBv1 Enabled (EternalBlue exposure class)",
        category="Network / Buffer Overflow",
        severity="warning",
        check=_check_smbv1_enabled,
        reference="CVE-2017-0144, MS17-010 (2017)",
    ),
    ConfigSignature(
        sig_id="SIG-102",
        cve_id="CVE-2019-0708",
        name="RDP Enabled Without NLA (BlueKeep exposure class)",
        category="Use-After-Free / Remote Code Execution",
        severity="warning",
        check=_check_rdp_without_nla,
        reference="CVE-2019-0708 (2019)",
    ),
    ConfigSignature(
        sig_id="SIG-103",
        cve_id="CVE-2020-0796",
        name="SMBv3 Compression Mitigation Not Set (SMBGhost exposure class)",
        category="Heap Memory Corruption / Wormable RCE",
        severity="warning",
        check=_check_smbv3_compression,
        reference="CVE-2020-0796, ADV200005 (Microsoft, 2020)",
    ),
]


def run_signature_scan() -> List[SignatureFinding]:
    """Runs both signature types and returns every match. Cheap enough to
    run on the same cadence as the known-vulnerability catalogue -- installed
    software and host config don't change from one scan to the next."""
    findings: List[SignatureFinding] = []

    installed = _installed_software()
    for name, version in installed:
        name_lower = name.lower()
        for sig in SOFTWARE_SIGNATURES:
            if sig.product_match not in name_lower:
                continue
            below = _version_below(version, sig.fixed_version)
            if below is not True:
                continue  # not vulnerable, or version unparsable -- don't guess
            findings.append(SignatureFinding(
                sig_id=sig.sig_id, cve_id=sig.cve_id, name=sig.name,
                severity=sig.severity,
                detail=f"{name} {version} installed (fixed in {sig.fixed_version}) -- "
                       f"{sig.description} [{sig.reference}]",
            ))

    for csig in CONFIG_SIGNATURES:
        try:
            detail = csig.check()
        except Exception as e:
            detail = None
            _ = e
        if detail:
            findings.append(SignatureFinding(
                sig_id=csig.sig_id, cve_id=csig.cve_id, name=csig.name,
                severity=csig.severity,
                detail=f"{detail} [{csig.reference}]",
            ))

    return findings
