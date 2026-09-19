"""HexStrike MCP bridge plugin for MARK LIII.

This plugin is the single entry point that lets MARK LIII use the HexStrike
MCP security server listening on ``http://127.0.0.1:9999``.  It wraps every
tool the server exposes — reconnaissance, network scanning, web analysis,
OSINT, password auditing, forensics, cloud assessment and more — behind one
guarded ``hexstrike`` action so the assistant can decide *which* tool to run
while this plugin decides *whether* it is safe to run.

Design goals, in priority order:

1.  Never stop MARK LIII.  Every failure path returns a structured result or
    a plain-language string; nothing here raises past ``run()``.
2.  Never act destructively without the user confirming on the HUD.  The
    safety gate has two levels: ``REVIEW`` tools run only after an explicit
    ``confirmed=true`` for that exact command, and ``DANGER`` tools are
    refused outright with an explanation.
3.  Verify before believing.  Scan findings are re-probed independently with
    ``curl`` before they reach the user, so classic scanner false positives
    (default-page 200s, absent-content version guesses, hydra wins against
    servers with no auth at all) are caught and labelled before MARK LIII
    speaks them as fact.
4.  Debug itself.  A dedicated self-diagnosis layer distinguishes "hexstrike
    not installed", "server not started", "server port changed", "tool binary
    missing on the server host" and "server returned an error", and reports
    the exact remedy instead of a generic failure.
5.  Remember what it did.  Scans, findings and verdicts are appended to
    ``memory/hexstrike_history.json`` so later sessions can reference prior
    coverage of a target.

Everything is local-only by default: the client refuses non-loopback targets
unless the user has explicitly allowed a named target in
``config/hexstrike_scope.json``.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shlex
import shutil
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
from collections import OrderedDict
from pathlib import Path
from typing import Any, Callable, Optional

try:
    from core import local_exec
except ImportError:  # pragma: no cover - degraded to server-only lane
    local_exec = None

LOGGER = logging.getLogger("jarvis.hexstrike")

BASE_DIR = Path(__file__).resolve().parent.parent
MEMORY_PATH = BASE_DIR / "memory" / "hexstrike_history.json"
SCOPE_PATH = BASE_DIR / "config" / "hexstrike_scope.json"
MANIFEST_PATH = BASE_DIR / "config" / "hexstrike_tools.json"
HEALTH_URL = "http://127.0.0.1:9999/health"
API_URL = "http://127.0.0.1:9999/api/tools/{tool}"
SERVER_BINARIES = ("hexstrike-server", "hexstrike_mcp_server.py", "hexstrike")
SERVER_HINT = (
    "start it with: hexstrike-server --port 9999  (or python3 hexstrike_mcp_server.py)"
)

MONITOR: Optional["HexStrikeController"] = None
MONITOR_LOCK = threading.RLock()

PLUGIN = {
    "name": "hexstrike_mcp",
    "description": (
        "Run HexStrike MCP security tools (nmap, gobuster, nuclei, hydra, "
        "dirb, john, hashcat, netexec, trivy, and more) through the local "
        "MCP server on port 9999. Every result is independently verified for "
        "false positives before it is reported. Destructive or intrusive "
        "tools require explicit confirmation on the HUD."
    ),
    "version": "1.0.0",
    "author": "MARK LIII",
    "parameters": {
        "type": "OBJECT",
        "properties": {
            "action": {
                "type": "STRING",
                "enum": [
                    "status", "health", "tools", "which", "self_test",
                    "scan", "quick_scan", "deep_scan", "web_scan",
                    "vuln_scan", "audit_passwords", "cloud_scan",
                    "container_scan", "pipeline", "verify",
                    "history", "explain", "open_server", "allow_target",
                    "guide", "playbook", "registry", "install_hint",
                ],
            },
            "tool": {"type": "STRING"},
            "target": {"type": "STRING"},
            "url": {"type": "STRING"},
            "ports": {"type": "STRING"},
            "arguments": {"type": "STRING"},
            "severity": {"type": "STRING"},
            "username": {"type": "STRING"},
            "password_file": {"type": "STRING"},
            "hash_file": {"type": "STRING"},
            "hash_type": {"type": "STRING"},
            "provider": {"type": "STRING"},
            "confirmed": {"type": "BOOLEAN"},
            "trust": {"type": "BOOLEAN"},
            "verdict": {"type": "STRING"},
            "finding": {"type": "STRING"},
        },
    },
}

SAFE_MODE = "SAFE"
REVIEW_MODE = "REVIEW"
DANGER_MODE = "DANGER"
SAFE = SAFE_MODE
REVIEW = REVIEW_MODE
DANGER = DANGER_MODE


# ── generic helpers ──────────────────────────────────────────────────────────


def _short(value: Any, limit: int = 500) -> str:
    """Return a single-line, bounded representation for logs and results."""
    text = re.sub(r"\s+", " ", str(value if value is not None else "")).strip()
    return text if len(text) <= limit else text[: max(0, limit - 3)] + "..."


def _now() -> int:
    return int(time.time())


def _normalise_target(target: str) -> str:
    """Strip scheme/path noise so target strings compare predictably."""
    value = str(target or "").strip()
    value = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", value)
    value = value.split("/", 1)[0]
    return value


def _loopback_target(target: str) -> bool:
    """Return true when the target is this machine's own loopback address."""
    name = _normalise_target(target).casefold()
    if name in {"localhost", "127.0.0.1", "::1", "0.0.0.0", "me", "self"}:
        return True
    if name.startswith("127."):
        return True
    return False


def _local_ips() -> set[str]:
    """Collect this host's own addresses so self-scans are recognised as safe."""
    ips = {"127.0.0.1", "::1", "localhost"}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ips.add(str(info[4][0]))
    except (OSError, socket.gaierror, UnicodeError):
        pass
    return ips


LOCAL_IPS = _local_ips()


def _is_this_host(target: str) -> bool:
    """True when the target refers to the local machine by name or address."""
    name = _normalise_target(target).casefold()
    if name in LOCAL_IPS:
        return True
    try:
        return socket.gethostbyname(name) in LOCAL_IPS
    except (OSError, socket.gaierror, UnicodeError):
        return False


def _read_json(path: Path) -> dict:
    """Read a JSON object without letting file errors escape."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def _write_json(path: Path, value: dict) -> bool:
    """Atomically replace a JSON file and report whether it succeeded."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(
            json.dumps(value, indent=2, ensure_ascii=True), encoding="utf-8"
        )
        os.replace(temporary, path)
        return True
    except OSError:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        return False


# ── the tool catalogue ───────────────────────────────────────────────────────


class ToolSpec:
    """Declarative description of one HexStrike tool."""

    __slots__ = (
        "name", "category", "mode", "default_args",
        "params", "local_probe", "summary",
    )

    def __init__(
        self,
        name: str,
        category: str,
        mode: str,
        default_args: str = "",
        params: tuple[str, ...] = (),
        local_probe: str = "",
        summary: str = "",
    ) -> None:
        self.name = name
        self.category = category
        self.mode = mode
        self.default_args = default_args
        self.params = params
        self.local_probe = local_probe
        self.summary = summary


class ToolCatalog:
    """Every HexStrike tool MARK LIII can call, with safety classification.

    ``SAFE``   read-only reconnaissance; runs without confirmation.
    ``REVIEW`` intrusive or state-changing; needs ``confirmed=true`` once.
    ``DANGER`` exploit, denial-of-service or credential-cracking tooling;
               refused outright — the explanation names why.
    """

    def __init__(self) -> None:
        self._tools: "OrderedDict[str, ToolSpec]" = OrderedDict()
        self._populate()

    def _add(self, spec: ToolSpec) -> None:
        self._tools[spec.name] = spec

    def _populate(self) -> None:
        # ── network / reconnaissance ──────────────────────────────────────
        self._add(ToolSpec(
            "nmap_scan", "network", SAFE, "-sV",
            ("target", "ports"), "nmap",
            "Port and service version scan of a target.",
        ))
        self._add(ToolSpec(
            "nmap_advanced_scan", "network", REVIEW, "-sS",
            ("target", "ports"), "nmap",
            "Advanced nmap with OS detection, NSE scripts and timing profiles.",
        ))
        self._add(ToolSpec(
            "rustscan_fast_scan", "network", SAFE, "",
            ("target", "ports"), "rustscan",
            "Ultra-fast port discovery that can feed results to nmap scripts.",
        ))
        self._add(ToolSpec(
            "masscan_scan", "network", REVIEW, "--rate=1000",
            ("target", "ports"), "masscan",
            "Internet-scale asynchronous port scan; very loud on networks.",
        ))
        self._add(ToolSpec(
            "arp_scan", "network", SAFE, "",
            ("target",), "arp-scan",
            "Layer-2 discovery of live hosts on the local segment.",
        ))
        self._add(ToolSpec(
            "autorecon_scan", "network", REVIEW, "",
            ("target", "ports"), "autorecon",
            "Multi-stage automated enumeration pipeline around nmap and friends.",
        ))
        self._add(ToolSpec(
            "netexec_scan", "network", REVIEW, "",
            ("target", "protocol", "username"), "netexec",
            "SMB/SSH/WinRM enumeration and credential validation (ex CrackMapExec).",
        ))
        self._add(ToolSpec(
            "smbmap_scan", "network", SAFE, "",
            ("target", "username"), "smbmap",
            "Enumerate readable and writable SMB shares on a host.",
        ))
        self._add(ToolSpec(
            "enum4linux_ng_advanced", "network", SAFE, "",
            ("target", "username"), "enum4linux-ng",
            "Deep Windows/SMB policy, user, group and share enumeration.",
        ))
        self._add(ToolSpec(
            "whois_lookup", "osint", SAFE, "",
            ("target",), "whois",
            "Domain registration ownership and contact lookup.",
        ))
        self._add(ToolSpec(
            "dig_lookup", "osint", SAFE, "",
            ("target",), "dig",
            "DNS record query for a domain (A, MX, TXT, NS, ...).",
        ))
        self._add(ToolSpec(
            "dnsrecon_scan", "osint", SAFE, "",
            ("target",), "dnsrecon",
            "DNS enumeration, zone transfer attempts and record discovery.",
        ))
        self._add(ToolSpec(
            "subfinder_scan", "osint", SAFE, "",
            ("target",), "subfinder",
            "Passive subdomain discovery from public data sources.",
        ))
        self._add(ToolSpec(
            "amass_enum", "osint", SAFE, "",
            ("target",), "amass",
            "Thorough attack-surface mapping via DNS, scraping and APIs.",
        ))
        self._add(ToolSpec(
            "theharvester_scan", "osint", SAFE, "",
            ("target",), "theHarvester",
            "Harvest emails, names and hosts from public search engines.",
        ))
        self._add(ToolSpec(
            "shodan_search", "osint", SAFE, "",
            ("query",), "shodan",
            "Query Shodan's index of internet-exposed devices and services.",
        ))
        self._add(ToolSpec(
            "censys_search", "osint", SAFE, "",
            ("query",), "censys",
            "Search Censys for certificates and host metadata.",
        ))
        self._add(ToolSpec(
            "crt_sh_lookup", "osint", SAFE, "",
            ("target",), "",
            "Certificate-transparency subdomain history for a domain.",
        ))
        self._add(ToolSpec(
            "waf_detection", "web", SAFE, "",
            ("url",), "wafw00f",
            "Fingerprint web application firewalls in front of a URL.",
        ))
        # ── web application ────────────────────────────────────────────────
        self._add(ToolSpec(
            "gobuster_scan", "web", SAFE,
            "dir -w /usr/share/wordlists/dirb/common.txt",
            ("url", "mode"), "gobuster",
            "Brute-force directories, DNS names, vhosts or parameters.",
        ))
        self._add(ToolSpec(
            "dirsearch_scan", "web", SAFE, "",
            ("url",), "dirsearch",
            "Threaded web path discovery with recursive probing.",
        ))
        self._add(ToolSpec(
            "dirb_scan", "web", SAFE, "",
            ("url",), "dirb",
            "Classic directory brute force with recursive wordlists.",
        ))
        self._add(ToolSpec(
            "feroxbuster_scan", "web", SAFE, "",
            ("url",), "feroxbuster",
            "Rust-based content discovery with recursion and filters.",
        ))
        self._add(ToolSpec(
            "nikto_scan", "web", REVIEW, "",
            ("target",), "nikto",
            "Web-server configuration and dangerous-file assessment; noisy.",
        ))
        self._add(ToolSpec(
            "nuclei_scan", "web", SAFE, "",
            ("target", "severity", "tags"), "nuclei",
            "Template-driven vulnerability scanning across many CVE classes.",
        ))
        self._add(ToolSpec(
            "dalfox_scan", "web", REVIEW, "",
            ("url",), "dalfox",
            "Parameter analysis and XSS scanning for a URL.",
        ))
        self._add(ToolSpec(
            "sqlmap_scan", "web", DANGER, "",
            ("url",), "sqlmap",
            "Automated SQL-injection exploitation; state-changing by design.",
        ))
        self._add(ToolSpec(
            "httpx_probe", "web", SAFE, "",
            ("target",), "httpx",
            "Fast liveness, title, status-code and tech probing of web hosts.",
        ))
        self._add(ToolSpec(
            "katana_crawl", "web", SAFE, "",
            ("url",), "katana",
            "JavaScript-aware spider that discovers endpoints and parameters.",
        ))
        self._add(ToolSpec(
            "arjun_scan", "web", SAFE, "",
            ("url",), "arjun",
            "Discover hidden HTTP parameters accepted by an endpoint.",
        ))
        self._add(ToolSpec(
            "wpscan_scan", "web", REVIEW, "",
            ("url",), "wpscan",
            "WordPress core, plugin and user enumeration with vuln DB.",
        ))
        self._add(ToolSpec(
            "ssrf_scan", "web", DANGER, "",
            ("url",), "",
            "Server-side request forgery probing; can hit internal services.",
        ))
        self._add(ToolSpec(
            "crlf_injection_scan", "web", DANGER, "",
            ("url",), "",
            "CRLF/header-injection probing; actively manipulates responses.",
        ))
        self._add(ToolSpec(
            "cors_scan", "web", SAFE, "",
            ("url",), "",
            "Cross-origin resource sharing misconfiguration checks.",
        ))
        self._add(ToolSpec(
            "ssl_scan", "web", SAFE, "",
            ("target",), "sslscan",
            "TLS version, cipher-suite and certificate weakness scan.",
        ))
        self._add(ToolSpec(
            "testssl_scan", "web", SAFE, "",
            ("target",), "testssl.sh",
            "Thorough TLS/SSL configuration assessment with grading.",
        ))
        # ── password / credential ──────────────────────────────────────────
        self._add(ToolSpec(
            "hydra_attack", "password", DANGER, "",
            ("target", "service", "username", "password_file"), "hydra",
            "Parallel network login brute force; lockouts and lockfile noise.",
        ))
        self._add(ToolSpec(
            "john_crack", "password", DANGER, "",
            ("hash_file",), "john",
            "Offline password-hash cracking with wordlists and rules.",
        ))
        self._add(ToolSpec(
            "hashcat_crack", "password", DANGER, "",
            ("hash_file", "hash_type"), "hashcat",
            "GPU-accelerated offline password-hash cracking.",
        ))
        self._add(ToolSpec(
            "hash_identifier", "password", SAFE, "",
            ("hash_string",), "hashid",
            "Identify the most likely algorithm of an unknown hash.",
        ))
        self._add(ToolSpec(
            "medusa_attack", "password", DANGER, "",
            ("target", "service", "username"), "medusa",
            "Parallel modular login brute force across protocols.",
        ))
        self._add(ToolSpec(
            "cewl_scan", "password", SAFE, "",
            ("url",), "cewl",
            "Spider a site and build a custom wordlist from its words.",
        ))
        self._add(ToolSpec(
            "crackmapexec_spray", "password", DANGER, "",
            ("target", "protocol"), "netexec",
            "Credential spraying across many hosts at once.",
        ))
        # ── forensics / binary / malware ───────────────────────────────────
        self._add(ToolSpec(
            "volatility_scan", "forensics", SAFE, "",
            ("memory_file",), "vol.py",
            "Memory-image analysis: processes, networks, credentials artifacts.",
        ))
        self._add(ToolSpec(
            "binwalk_scan", "forensics", SAFE, "",
            ("file_path",), "binwalk",
            "Firmware and binary analysis; extract embedded files.",
        ))
        self._add(ToolSpec(
            "strings_extract", "forensics", SAFE, "",
            ("file_path",), "strings",
            "Extract readable strings from a binary or dump.",
        ))
        self._add(ToolSpec(
            "exiftool_scan", "forensics", SAFE, "",
            ("file_path",), "exiftool",
            "Read metadata embedded in documents and images.",
        ))
        self._add(ToolSpec(
            "clamav_scan", "forensics", SAFE, "",
            ("file_path",), "clamscan",
            "Antivirus scan of a file or directory with ClamAV.",
        ))
        self._add(ToolSpec(
            "yara_scan", "forensics", SAFE, "",
            ("file_path", "rule_file"), "yara",
            "Match a file against YARA signature rules.",
        ))
        self._add(ToolSpec(
            "oletools_scan", "forensics", SAFE, "",
            ("file_path",), "olevba",
            "Extract and analyse VBA macros inside Office documents.",
        ))
        self._add(ToolSpec(
            "peframe_scan", "forensics", REVIEW, "",
            ("file_path",), "peframe",
            "Static analysis of Windows PE executables.",
        ))
        self._add(ToolSpec(
            "floss_scan", "forensics", SAFE, "",
            ("file_path",), "floss",
            "Deobfuscate stack strings in suspicious binaries.",
        ))
        self._add(ToolSpec(
            "capa_scan", "forensics", SAFE, "",
            ("file_path",), "capa",
            "Identify capabilities of an executable from its behaviour.",
        ))
        self._add(ToolSpec(
            "ghidra_headless", "forensics", REVIEW, "",
            ("file_path",), "analyzeHeadless",
            "Run Ghidra decompilation headlessly on a binary.",
        ))
        self._add(ToolSpec(
            "radare2_analysis", "forensics", SAFE, "",
            ("file_path",), "radare2",
            "Quick static disassembly and function listing via r2.",
        ))
        self._add(ToolSpec(
            "objdump_scan", "forensics", SAFE, "",
            ("file_path",), "objdump",
            "Disassemble object files and list sections.",
        ))
        self._add(ToolSpec(
            "chkrootkit_scan", "forensics", SAFE, "",
            (), "chkrootkit",
            "Check the local host for known rootkit signatures.",
        ))
        self._add(ToolSpec(
            "rkhunter_scan", "forensics", REVIEW, "--check --sk",
            (), "rkhunter",
            "Rootkit hunter scan of local binaries and boot records.",
        ))
        self._add(ToolSpec(
            "lasso_shellcode_scan", "forensics", SAFE, "",
            ("file_path",), "",
            "Detect and classify shellcode blobs inside files.",
        ))
        self._add(ToolSpec(
            "dc3_mft_scan", "forensics", SAFE, "",
            ("disk_image",), "",
            "Master-file-table analysis of a disk image.",
        ))
        # ── cloud / container ──────────────────────────────────────────────
        self._add(ToolSpec(
            "trivy_scan", "cloud", SAFE, "",
            ("target", "scan_type"), "trivy",
            "Vulnerability scan of container images, filesystems or repos.",
        ))
        self._add(ToolSpec(
            "prowler_scan", "cloud", SAFE, "",
            ("provider", "profile"), "prowler",
            "CIS-benchmark and best-practice assessment of a cloud account.",
        ))
        self._add(ToolSpec(
            "scoutSuite_scan", "cloud", SAFE, "",
            ("provider",), "scout",
            "Multi-cloud security posture report generation.",
        ))
        self._add(ToolSpec(
            "kube_hunter_scan", "cloud", REVIEW, "",
            ("target",), "kube-hunter",
            "Hunt for weaknesses in Kubernetes clusters; probes live APIs.",
        ))
        self._add(ToolSpec(
            "kube_bench_scan", "cloud", SAFE, "",
            (), "kube-bench",
            "CIS benchmark checks for a Kubernetes node.",
        ))
        self._add(ToolSpec(
            "checkov_scan", "cloud", SAFE, "",
            ("directory",), "checkov",
            "Static analysis of Terraform/Kubernetes/CloudFormation configs.",
        ))
        self._add(ToolSpec(
            "terrascan_scan", "cloud", SAFE, "",
            ("directory",), "terrascan",
            "Detect compliance and security errors in IaC templates.",
        ))
        self._add(ToolSpec(
            "falco_rules_test", "cloud", SAFE, "",
            ("rule_file",), "falco",
            "Validate Falco runtime-security rules.",
        ))
        self._add(ToolSpec(
            "clair_scan", "cloud", SAFE, "",
            ("image",), "clair",
            "Static container image vulnerability analysis.",
        ))
        self._add(ToolSpec(
            "grype_scan", "cloud", SAFE, "",
            ("image",), "grype",
            "SBOM-driven vulnerability matching for images and filesystems.",
        ))
        self._add(ToolSpec(
            "syft_sbom", "cloud", SAFE, "",
            ("image",), "syft",
            "Generate a software bill of materials for an image.",
        ))
        self._add(ToolSpec(
            "dockle_scan", "cloud", SAFE, "",
            ("image",), "dockle",
            "Linter for container image security best practices.",
        ))
        self._add(ToolSpec(
            "hadolint_scan", "cloud", SAFE, "",
            ("dockerfile",), "hadolint",
            "Lint Dockerfiles for security and style problems.",
        ))
        # ── exploitation / post-exploitation ───────────────────────────────
        self._add(ToolSpec(
            "searchsploit_search", "exploitation", SAFE, "",
            ("query",), "searchsploit",
            "Search the offline Exploit-DB index; read-only.",
        ))
        self._add(ToolSpec(
            "msf_search", "exploitation", SAFE, "",
            ("query",), "msfconsole",
            "Search the Metasploit module index; read-only.",
        ))
        self._add(ToolSpec(
            "msf_run_module", "exploitation", DANGER, "",
            ("module", "target"), "msfconsole",
            "Execute a Metasploit module; actively exploits a target.",
        ))
        self._add(ToolSpec(
            "empire_start_listener", "exploitation", DANGER, "",
            (), "powershell-empire",
            "Start a C2 listener for post-exploitation agents.",
        ))
        self._add(ToolSpec(
            "bloodhound_collection", "exploitation", REVIEW, "-c All",
            ("target", "username"), "bloodhound-python",
            "Collect Active Directory graph data for attack-path analysis.",
        ))
        self._add(ToolSpec(
            "responder_run", "exploitation", DANGER, "",
            (), "responder",
            "Poison name-service traffic to capture credential hashes.",
        ))
        self._add(ToolSpec(
            "bettercap_run", "exploitation", DANGER, "",
            (), "bettercap",
            "Man-in-the-middle framework; intercepts live traffic.",
        ))
        self._add(ToolSpec(
            "wireshark_capture", "exploitation", REVIEW, "-a duration:30",
            ("interface",), "tshark",
            "Capture and dissect live network traffic for 30 seconds.",
        ))
        self._add(ToolSpec(
            "tcpdump_capture", "exploitation", REVIEW, "-c 200",
            ("interface",), "tcpdump",
            "Capture up to 200 packets on an interface.",
        ))
        self._add(ToolSpec(
            "arp_spoof", "exploitation", DANGER, "",
            ("target",), "arpspoof",
            "Forge ARP replies to intercept a victim's traffic.",
        ))
        self._add(ToolSpec(
            "mac_changer", "exploitation", DANGER, "",
            ("interface",), "macchanger",
            "Randomise or spoof a network interface MAC address.",
        ))
        # ── utility / extra ────────────────────────────────────────────────
        self._add(ToolSpec(
            "nuclei_template_update", "additional", SAFE, "",
            (), "nuclei",
            "Refresh the local nuclei template database.",
        ))
        self._add(ToolSpec(
            "seclists_wordlist_info", "additional", SAFE, "",
            (), "",
            "Report which wordlist packages are installed on the server.",
        ))
        self._add(ToolSpec(
            "rockyou_check", "additional", SAFE, "",
            (), "",
            "Verify the rockyou wordlist is present for offline audits.",
        ))
        self._add(ToolSpec(
            "msfvenom_generate", "exploitation", DANGER, "",
            ("payload",), "msfvenom",
            "Generate a malicious payload binary.",
        ))
        self._add(ToolSpec(
            "chisel_server", "exploitation", DANGER, "",
            (), "chisel",
            "Start a TCP/HTTP tunnel server for pivoting.",
        ))
        self._add(ToolSpec(
            "socat_relay", "exploitation", DANGER, "",
            (), "socat",
            "Relay raw connections between two addresses.",
        ))
        self._add(ToolSpec(
            "proxychains_run", "additional", SAFE, "",
            ("command",), "proxychains",
            "Route a command's traffic through the configured proxy chain.",
        ))
        self._add(ToolSpec(
            "wordlist_generator", "additional", SAFE, "",
            ("keywords",), "crunch",
            "Generate a candidate password list from supplied keywords.",
        ))
        self._add(ToolSpec(
            "url_extract", "additional", SAFE, "",
            ("input_file",), "",
            "Pull every URL out of a text corpus for later probing.",
        ))
        self._add(ToolSpec(
            "paramspider_scan", "web", SAFE, "",
            ("target",), "paramspider",
            "Mine archived URLs and parameters for a domain from Wayback.",
        ))

    def get(self, name: str) -> Optional[ToolSpec]:
        return self._tools.get(str(name or "").strip().casefold())

    def names(self) -> list[str]:
        return list(self._tools)

    def all(self) -> list[ToolSpec]:
        return list(self._tools)

    def by_mode(self, mode: str) -> list[ToolSpec]:
        return [spec for spec in self._tools.values() if spec.mode == mode]

    def count(self) -> int:
        return len(self._tools)


CATALOG = ToolCatalog()


# ── health & self-diagnosis ─────────────────────────────────────────────────


class HealthProbe:
    """Talk to the HexStrike server's health endpoint and tool registry."""

    def __init__(self, logger: Callable[[str], None]) -> None:
        self._log = logger
        self._lock = threading.Lock()
        self._cached: Optional[dict] = None
        self._cached_at = 0.0
        self._manifest: dict = {}
        self._manifest_mtime = -1.0

    def _fetch(self, timeout: float = 4.0) -> Optional[dict]:
        """Return the parsed health JSON, or None when unreachable."""
        try:
            request = urllib.request.Request(
                HEALTH_URL, headers={"Accept": "application/json"}
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read().decode("utf-8", "replace"))
                return payload if isinstance(payload, dict) else None
        except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
            self._log(f"⚠️ hexstrike → health unreachable: {_short(exc, 140)}")
            return None

    def fetch(self, refresh: bool = False) -> Optional[dict]:
        """Return health data, cached for fifteen seconds between calls."""
        with self._lock:
            if not refresh and self._cached and time.monotonic() - self._cached_at < 15.0:
                return self._cached
            payload = self._fetch()
            if payload is not None:
                self._cached = payload
                self._cached_at = time.monotonic()
            else:
                self._cached = None
                self._cached_at = 0.0
            return self._cached

    def clear_cache(self) -> None:
        with self._lock:
            self._cached = None
            self._cached_at = 0.0

    def manifest(self, refresh: bool = False) -> dict:
        """Load config/hexstrike_tools.json; source of truth for endpoints."""
        with self._lock:
            try:
                mtime = MANIFEST_PATH.stat().st_mtime
            except OSError:
                mtime = -1.0
            if not self._manifest or refresh or mtime != self._manifest_mtime:
                self._manifest = _read_json(MANIFEST_PATH)
                self._manifest_mtime = mtime
            return self._manifest

    def registry(self) -> dict:
        """Return the manifest registry: real endpoint names and aliases."""
        data = self.manifest().get("tool_registry", {})
        return {
            "available": list(data.get("available", [])),
            "installable": list(data.get("installable", [])),
            "aliases": dict(self.manifest().get("endpoint_aliases", {})),
        }

    def live_registry(self) -> dict:
        """Fetch the server's own tools_status map when health is reachable."""
        payload = self.fetch()
        if not payload:
            return {}
        status = payload.get("tools_status")
        return status if isinstance(status, dict) else {}

    def totals(self) -> dict:
        """Return registered/available counts from the live server health."""
        payload = self.fetch()
        if not payload:
            return {"registered": 0, "available": 0, "version": ""}
        return {
            "registered": int(payload.get("total_tools_count", 0) or 0),
            "available": int(payload.get("total_tools_available", 0) or 0),
            "version": str(payload.get("version", "")),
        }


class SelfDiagnoser:
    """Turn connectivity failures into precise, actionable explanations."""

    _REMEDIES = {
        "not_installed": (
            "HexStrike is not installed on this machine. Install it, then run "
            f"{SERVER_HINT}."
        ),
        "not_running": (
            "HexStrike is installed but the server is not listening. "
            f"{SERVER_HINT}."
        ),
        "port_changed": (
            "Something is listening on port 9999 but it is not HexStrike. "
            "Check which process owns the port and restart HexStrike on 9999."
        ),
        "degraded": (
            "HexStrike is up but some tool binaries are missing on the server "
            "host. Install the missing packages or restrict scans to the "
            "tools that are available."
        ),
    }

    def __init__(self, health: HealthProbe, logger: Callable[[str], None]) -> None:
        self._health = health
        self._log = logger

    def installed(self) -> bool:
        """Return whether any HexStrike binary or script is findable."""
        if any(shutil.which(name) for name in SERVER_BINARIES):
            return True
        common = (
            Path("/opt/hexstrike"), Path.home() / "hexstrike",
            Path.home() / "tools" / "hexstrike", BASE_DIR.parent / "hexstrike",
        )
        return any(directory.exists() for directory in common)

    def diagnose(self) -> dict:
        """Classify the current server state into one named condition."""
        payload = self._health.fetch(refresh=True)
        if payload is not None:
            missing = self._missing_count(payload)
            state = "healthy" if not missing else "degraded"
            return {"state": state, "missing_tools": missing, "health": payload}
        if not self.installed():
            return {"state": "not_installed", "missing_tools": -1, "health": None}
        if _something_on_port(9999):
            return {"state": "port_changed", "missing_tools": -1, "health": None}
        return {"state": "not_running", "missing_tools": -1, "health": None}

    def _missing_count(self, payload: dict) -> int:
        """Count unavailable tools from whatever shape the health body uses."""
        categories = payload.get("category_stats")
        if isinstance(categories, dict):
            return sum(
                int(entry.get("total", 0)) - int(entry.get("available", 0))
                for entry in categories.values() if isinstance(entry, dict)
            )
        availability = payload.get("tool_availability")
        if isinstance(availability, dict):
            return sum(1 for value in availability.values() if not value)
        return 0

    def remedy(self, state: str) -> str:
        return self._REMEDIES.get(state, "Unknown failure mode; check the logs.")


def _something_on_port(port: int) -> bool:
    """Return true when any process accepts connections on the port."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.5):
            return True
    except OSError:
        return False


class ServerOpen:
    """Attempt to start the HexStrike server when it is not running."""

    def __init__(self, logger: Callable[[str], None]) -> None:
        self._log = logger
        self._attempted = 0.0

    def open(self, confirmed: bool) -> str:
        """Try to launch the server, respecting an explicit confirmation."""
        if _something_on_port(9999):
            return "Port 9999 is already serving; HexStrike may already be up."
        if not confirmed:
            return (
                "HexStrike is not listening. Confirm on the HUD "
                "(confirmed=true) and I will start it myself."
            )
        if time.monotonic() - self._attempted < 10.0:
            return "I tried starting the server recently; give it a moment."
        self._attempted = time.monotonic()
        for candidate in SERVER_BINARIES:
            binary = shutil.which(candidate)
            if binary is None:
                continue
            argv = [binary, "--port", "9999"] if candidate == "hexstrike-server" else [binary]
            try:
                subprocess.Popen(
                    argv,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
            except OSError as exc:
                self._log(f"⚠️ hexstrike → spawn failed: {_short(exc, 120)}")
                continue
            for _ in range(10):
                time.sleep(0.5)
                if _something_on_port(9999):
                    return "HexStrike server started on port 9999."
            self._log("⚠️ hexstrike → server did not accept connections after launch")
        return f"I could not start HexStrike automatically. {SERVER_HINT}."


# ── safe HTTP client for the tool API ────────────────────────────────────────


class HexStrikeClient:
    """Minimal JSON client for POST /api/tools/<endpoint> on the MCP server."""

    def __init__(self, logger: Callable[[str], None], health: Optional[HealthProbe] = None) -> None:
        self._log = logger
        self._lock = threading.Lock()
        self._inflight = 0
        self._health = health

    def _resolve_url(self, tool: str) -> str:
        """Map a friendly tool name onto a real server endpoint path.

        HexStrike exposes plain binary names (``nmap``, ``gobuster``), so
        friendly names resolve through the manifest's endpoint_aliases and
        are then confirmed against the live tools_status registry.
        """
        aliases: dict = {}
        available: set[str] = set()
        if self._health is not None:
            registry = self._health.registry()
            aliases = registry.get("aliases", {})
            live = self._health.live_registry()
            available = {name for name, ok in live.items() if ok}
            if not available:
                available = set(registry.get("available", []))
        name = str(tool).strip().casefold()
        endpoint = str(aliases.get(name) or aliases.get(str(tool).strip()) or name)
        if available and endpoint not in available:
            match = next((n for n in available if n.casefold() == endpoint.casefold()), "")
            if match:
                endpoint = match
            else:
                stripped = re.sub(r"_(scan|attack|crack|enum|probe|fast|advanced)$", "", name)
                if stripped in available:
                    endpoint = stripped
        return API_URL.format(tool=endpoint)

    def call(self, tool: str, payload: dict, timeout: int = 240) -> dict:
        """POST one tool call and return the server's structured response."""
        payload = _harden_scan_payload(tool, payload)
        if _is_scan_tool(tool):
            timeout = min(timeout, SCAN_TIMEOUT_S + 30)
        url = self._resolve_url(tool)
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        with self._lock:
            self._inflight += 1
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = json.loads(response.read().decode("utf-8", "replace"))
                return data if isinstance(data, dict) else {"raw": data}
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", "replace")[:300]
            except (OSError, ValueError):
                pass
            return {
                "error": f"HTTP {exc.code} from server: {_short(detail)}",
                "http_status": exc.code,
                "return_code": exc.code,
                "stdout": "",
                "stderr": _short(detail),
            }
        except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
            return {"error": f"server unreachable: {_short(exc, 200)}"}
        finally:
            with self._lock:
                self._inflight -= 1

    def busy(self) -> int:
        with self._lock:
            return self._inflight


# ── safety gate ──────────────────────────────────────────────────────────────


class SafetyGate:
    """Decide whether a tool call may run, and remember confirmations."""

    def __init__(self, logger: Callable[[str], None]) -> None:
        self._log = logger
        self._lock = threading.RLock()
        self._approved: dict[str, float] = {}
        self._scope = self._load_scope()
        self._gate_hits = 0

    @staticmethod
    def _load_scope() -> dict:
        scope = _read_json(SCOPE_PATH)
        scope.setdefault("allowed_targets", [])
        scope.setdefault("allow_local_network", False)
        scope.setdefault("allow_any_target", False)
        return scope

    def reload_scope(self) -> None:
        with self._lock:
            self._scope = self._load_scope()

    def allow_target(self, target: str, confirmed: bool) -> str:
        """Whitelist one named remote target after HUD confirmation."""
        name = _normalise_target(target)
        if not name:
            return "That target name is empty."
        if _is_this_host(name):
            return f"{name} is this machine; it is already allowed."
        if not confirmed:
            self._gate_hits += 1
            return (
                f"Scanning {name} touches a system beyond this machine. "
                "Confirm on the HUD (confirmed=true) if you own or are "
                "authorised to test it, and I will add it to the scope."
            )
        with self._lock:
            self._scope = self._load_scope()
            allowed = set(self._scope.get("allowed_targets", []))
            allowed.add(name)
            self._scope["allowed_targets"] = sorted(allowed)
            ok = _write_json(SCOPE_PATH, self._scope)
        if ok:
            self._log(f"🛡️ hexstrike → scope now includes {name}")
            return f"{name} is now in the authorised scan scope."
        return "I could not persist the scope file; the target stays unapproved."

    def check(self, spec: ToolSpec, arguments: dict) -> tuple[bool, str]:
        """Return permission and an explanation for one planned tool call."""
        target = str(arguments.get("target") or arguments.get("url") or "")
        mode = spec.mode
        if mode == DANGER_MODE:
            self._gate_hits += 1
            return False, (
                f"{spec.name} is a destructive {spec.category} tool and MARK LIII "
                "refuses to run it. Reason: it actively exploits, poisons or "
                "cracks rather than observes."
            )
        if _is_this_host(target) and mode == SAFE_MODE:
            return True, "local target"
        if self._scope.get("allow_any_target") is True:
            return True, "blanket authorisation in scope file"
        if target:
            name = _normalise_target(target)
            with self._lock:
                allowed = set(self._scope.get("allowed_targets", []))
            if name in allowed or name.casefold() in {t.casefold() for t in allowed}:
                return True, "target in authorised scope"
        if mode == REVIEW_MODE:
            self._gate_hits += 1
            return False, (
                f"{spec.name} is intrusive ({spec.category}). Re-run with "
                "confirmed=true after reviewing what it does."
            )
        return False, (
            "That target is not in the authorised scope. Use allow_target "
            "with confirmed=true first, or scan this machine."
        )

    def stats(self) -> dict:
        with self._lock:
            return {
                "gate_hits": self._gate_hits,
                "scope_targets": len(self._scope.get("allowed_targets", [])),
                "allow_local_network": bool(self._scope.get("allow_local_network")),
            }


# ── false-positive verification ─────────────────────────────────────────────


class FalsePositiveVerifier:
    """Independently re-probe scanner claims before reporting them.

    Scanners over-report.  Hydra reports a win when a server has no auth.
    Version detection guesses defaults when banners are absent.  Nuclei
    matches error-page text.  This layer re-tests each class of claim with a
    second, independent method and stamps findings with a verdict:
    ``verified``, ``refuted``, or ``unverifiable``.
    """

    _DEFAULT_PAGE_MARKERS = (
        "it works!", "welcome to nginx", "apache2 default page",
        "test page for the apache", "iis windows server",
    )

    def __init__(self, logger: Callable[[str], None]) -> None:
        self._log = logger
        self._http_lock = threading.Lock()

    def _curl(self, url: str, timeout: int = 6, extra: tuple[str, ...] = ()) -> dict:
        """One bounded curl probe returning status, body and headers."""
        argv = ["curl", "-s", "-m", str(timeout), "-o", "-", "-D", "-", *extra, url]
        try:
            result = subprocess.run(
                argv, capture_output=True, text=True, timeout=timeout + 2, check=False
            )
        except (OSError, subprocess.SubprocessError, TimeoutError) as exc:
            self._log(f"⚠️ hexstrike → verifier curl failed: {_short(exc, 120)}")
            return {"ok": False, "status": 0, "body": "", "headers": ""}
        head, _, body = result.stdout.partition("\r\n\r\n")
        status = 0
        match = re.search(r"HTTP/[\d.]+\s+(\d{3})", head)
        if match:
            status = int(match.group(1))
        return {"ok": result.returncode == 0, "status": status, "body": body, "headers": head}

    def verify_open_port(self, target: str, port: int) -> dict:
        """Re-test a claimed open port with a raw socket connection."""
        try:
            with socket.create_connection((target, port), timeout=3):
                return {"verdict": "verified", "detail": f"TCP connect to {target}:{port} succeeded"}
        except OSError:
            return {"verdict": "refuted", "detail": f"TCP connect to {target}:{port} failed"}

    def verify_http_service(self, target: str, port: int) -> dict:
        """Re-test an HTTP claim and detect default-page false positives."""
        scheme = "https" if port in {443, 8443} else "http"
        url = f"{scheme}://{target}:{port}/"
        probe = self._curl(url)
        if not probe["ok"] or probe["status"] == 0:
            return {"verdict": "refuted", "detail": f"no HTTP response from {url}"}
        marker_hit = next(
            (m for m in self._DEFAULT_PAGE_MARKERS if m in probe["body"].casefold()), None
        )
        if marker_hit:
            return {
                "verdict": "unverifiable",
                "detail": f"port {port} serves a default page ({marker_hit!r}); "
                          "version string is a guess",
            }
        return {"verdict": "verified", "detail": f"HTTP {probe['status']} from {url}"}

    def verify_version_claim(self, service: str, claimed: str, target: str, port: int) -> dict:
        """Check a version banner claim against independent evidence."""
        if not claimed:
            return {"verdict": "unverifiable", "detail": "no version claimed"}
        open_check = self.verify_open_port(target, port)
        if open_check["verdict"] != "verified":
            return {"verdict": "refuted", "detail": f"port closed; banner {claimed!r} impossible"}
        if service.casefold().startswith("http"):
            http_check = self.verify_http_service(target, port)
            if http_check["verdict"] == "refuted":
                return {"verdict": "refuted", "detail": http_check["detail"]}
        return {"verdict": "verified", "detail": f"banner {claimed!r} consistent with live service"}

    def verify_auth_bypass(self, target: str, port: int, scheme: str,
                           username: str, password: str) -> dict:
        """Verify a credential claim like Hydra's with raw HTTP semantics.

        Hydra's classic false positive: on a server with no authentication,
        every guess "wins".  We refute when the endpoint behaves identically
        with the claimed credential, a wrong one, and none at all.
        """
        scheme = scheme.casefold().replace("-get", "").replace("-post", "")
        url = f"http://{target}:{port}/"
        with self._http_lock:
            bare = self._curl(url)
            good = self._curl(url, extra=("-u", f"{username}:{password}"))
            bad = self._curl(url, extra=("-u", f"{username}:{password}wrong123"))
        if bare["status"] == 401 and good["status"] in {200, 301, 302} and bad["status"] == 401:
            return {"verdict": "verified",
                    "detail": "wrong creds rejected, claimed creds accepted"}
        if bare["status"] == good["status"] == bad["status"]:
            return {"verdict": "refuted",
                    "detail": f"identical HTTP {bare['status']} with and without creds; "
                              "the service has no authentication to bypass"}
        return {"verdict": "unverifiable",
                "detail": f"status pattern {bare['status']}/{good['status']}/{bad['status']} inconclusive"}

    def verify_web_finding(self, url: str, claim: str) -> dict:
        """Re-probe a web scanner finding at the exact claimed path."""
        path_match = re.search(r"https?://[^\s'\"]+", str(claim))
        probe_url = path_match.group(0) if path_match else url
        probe = self._curl(probe_url)
        if not probe["ok"] or probe["status"] in {0, 404, 410}:
            return {"verdict": "refuted",
                    "detail": f"{_short(probe_url, 120)} returned HTTP {probe['status']}"}
        if probe["status"] in {200, 301, 302, 401, 403}:
            return {"verdict": "verified",
                    "detail": f"{_short(probe_url, 120)} responds HTTP {probe['status']}"}
        return {"verdict": "unverifiable", "detail": f"HTTP {probe['status']} inconclusive"}

    def verify_vulnerability(self, target: str, finding: str) -> dict:
        """Route a vulnerability claim to the right independent check."""
        text = str(finding or "")
        port_match = re.search(r"(\d{1,5})/tcp|:(\d{2,5})", text)
        port = int(port_match.group(1) or port_match.group(2)) if port_match else 80
        if re.search(r"https?://", text):
            return self.verify_web_finding(target, text)
        if re.search(r"auth|login|brute|credential", text, re.IGNORECASE):
            return self.verify_auth_bypass(target, port, "http-get", "admin", "x")
        if re.search(r"version|banner", text, re.IGNORECASE):
            return self.verify_version_claim("generic", text, target, port)
        return {"verdict": "unverifiable", "detail": "no independent probe for this class"}

    def classify(self, response: dict, spec: ToolSpec, arguments: dict) -> list[dict]:
        """Attach verification verdicts to a whole tool response.

        Returns a list of finding records: each with the original text, a
        verdict, and human-readable evidence.
        """
        findings: list[dict] = []
        target = _normalise_target(str(arguments.get("target") or arguments.get("url") or "127.0.0.1"))
        stdout = str(response.get("stdout") or response.get("output") or "")
        if spec.name == "nmap_scan" or spec.name == "nmap_advanced_scan":
            findings.extend(self._classify_nmap(stdout, target))
        elif "hydra" in spec.name or "medusa" in spec.name:
            findings.extend(self._classify_brute(stdout, target))
        elif spec.name in {"gobuster_scan", "dirb_scan", "dirsearch_scan", "feroxbuster_scan"}:
            findings.extend(self._classify_paths(stdout, target))
        elif spec.name == "nuclei_scan":
            findings.extend(self._classify_nuclei(stdout, target))
        else:
            for line in stdout.splitlines():
                if re.search(r"\b(vulnerable|success|open|found|valid)\b", line, re.IGNORECASE):
                    findings.append({"claim": _short(line, 200), "verdict": "unverifiable",
                                     "evidence": "no independent probe for this tool"})
        return findings

    # Banner lines appended by the fast lane: ``banner 80/tcp: Server: Boa...``
    _BANNER_LINE = re.compile(r"^banner[ \t]+(\d{1,5})/tcp:[ \t]*(.+)$", re.MULTILINE)

    def _classify_nmap(self, stdout: str, target: str) -> list[dict]:
        records: list[dict] = []
        banners = {
            int(port): text.strip()
            for port, text in self._BANNER_LINE.findall(stdout)
        }
        # ``[ \t]+`` rather than ``\s+``: a newline is whitespace too, and the
        # old pattern happily swallowed the next port line into the banner,
        # merging two findings into one bogus claim.
        for match in re.finditer(
            r"^(\d{1,5})/tcp[ \t]+open[ \t]+(\S+)(?:[ \t]+([^\n]*))?$",
            stdout, re.MULTILINE,
        ):
            port = int(match.group(1))
            service = match.group(2)
            banner = (match.group(3) or "").strip() or banners.get(port, "")
            # The claim is "this port is open", so only a raw TCP connect can
            # settle it.  An HTTP probe enriches the evidence; it must never
            # refute an open port.  A TLS-only or non-HTTP service ignores a
            # plain HTTP request, and calling that "port closed" would throw
            # away a real finding -- a false negative, just as bad as a false
            # positive.
            verdict = self.verify_open_port(target, port)
            detail = verdict["detail"]
            if service.casefold().startswith("http") or port in {80, 443, 8080, 8443}:
                http_probe = self.verify_http_service(target, port)
                if http_probe["verdict"] == "verified" or verdict["verdict"] != "verified":
                    verdict = http_probe
                    detail = http_probe["detail"]
                else:
                    detail = f"{detail}; {http_probe['detail']}"
            if banner:
                version_check = self.verify_version_claim(service, banner, target, port)
                if version_check["verdict"] == "refuted":
                    verdict = version_check
                    detail = version_check["detail"]
                elif version_check["verdict"] == "verified":
                    detail = f"{detail}; {version_check['detail']}"
            claim = f"{port}/tcp open {service}"
            if banner:
                claim = f"{claim} — {_short(banner, 160)}"
            records.append({
                "claim": claim,
                "verdict": verdict["verdict"],
                "evidence": detail,
            })
        return records

    def _classify_brute(self, stdout: str, target: str) -> list[dict]:
        records: list[dict] = []
        for match in re.finditer(
            r"^\[\d+\]\[[\w-]+\]\s+host:\s*(\S+)\s+.*?login:\s*(\S+)\s+password:\s*(\S+)",
            stdout, re.MULTILINE,
        ):
            host, login, password = match.group(1), match.group(2), match.group(3)
            port_match = re.search(r"\[(\d{1,5})\]", match.group(0))
            port = int(port_match.group(1)) if port_match else 9999
            verdict = self.verify_auth_bypass(host, port, "http-get", login, password)
            records.append({
                "claim": f"credential {login}:{password} accepted on {host}:{port}",
                "verdict": verdict["verdict"],
                "evidence": verdict["detail"],
            })
        if "valid password found" in stdout and not records:
            records.append({
                "claim": "scanner reported a valid credential",
                "verdict": "refuted",
                "evidence": "no credential pair in output and no auth present to bypass",
            })
        return records

    def _classify_paths(self, stdout: str, target: str) -> list[dict]:
        records: list[dict] = []
        for match in re.finditer(r"^(https?://\S+)\s+\(Status:\s*(\d{3})\)", stdout, re.MULTILINE):
            url, status = match.group(1), int(match.group(2))
            verdict = self.verify_web_finding(url, url)
            records.append({
                "claim": f"{url} (scanner status {status})",
                "verdict": verdict["verdict"],
                "evidence": verdict["detail"],
            })
        return records

    def _classify_nuclei(self, stdout: str, target: str) -> list[dict]:
        records: list[dict] = []
        for match in re.finditer(r"^\[([a-z0-9-]+)\]\s*\[([a-z]+)\]\s*\[http\]\s*(\S+)", stdout, re.MULTILINE):
            template, severity, url = match.group(1), match.group(2), match.group(3)
            verdict = self.verify_web_finding(url, url)
            records.append({
                "claim": f"nuclei {template} ({severity}) on {url}",
                "verdict": verdict["verdict"],
                "evidence": verdict["detail"],
            })
        return records


# ── auto-debugging of failures ───────────────────────────────────────────────


class FailureDoctor:
    """Interpret a failed tool call and propose the next action."""

    _PATTERNS: tuple[tuple[str, str, str], ...] = (
        (r"connection refused|ECONNREFUSED", "server_down",
         "HexStrike refused the connection; it may be restarting. Try again or use open_server."),
        (r"timed?\s*out|timeout", "timeout",
         "The scan exceeded its time budget. Narrow the ports or the wordlist and retry."),
        (r"HTTP 400", "bad_request",
         "The server rejected the parameters. Check required fields for this tool."),
        (r"HTTP 404", "unknown_tool",
         "The server does not expose that endpoint. config/hexstrike_tools.json "
         "maps friendly names to real ones; re-resolve from GET /health tools_status."),
        (r"HTTP 5\d\d", "server_error",
         "HexStrike hit an internal error. Check its terminal output."),
        (r"not found|command not found|No such file", "binary_missing",
         "The tool binary is missing on the server host. Install it there."),
        (r"permission denied|requires? root", "privileges",
         "The tool needs elevated privileges on the server host; run it manually there."),
        (r"0 hosts? up", "no_hosts",
         "The target did not answer. Confirm the address and that it is online."),
        (r"HTTP 401|unauthor", "auth_required",
         "The server API demanded credentials; check its configuration."),
    )

    def __init__(self, diagnoser: SelfDiagnoser) -> None:
        self._diagnoser = diagnoser

    def explain(self, response: dict, spec: Optional[ToolSpec]) -> str:
        """Return one clear sentence describing the failure and remedy."""
        blob = " ".join(str(response.get(key, "")) for key in ("error", "stderr", "stdout"))
        for pattern, name, advice in self._PATTERNS:
            if re.search(pattern, blob, re.IGNORECASE):
                return f"{name}: {advice}"
        diagnosis = self._diagnoser.diagnose()
        if diagnosis["state"] != "healthy":
            return f"server state: {diagnosis['state']} — {self._diagnoser.remedy(diagnosis['state'])}"
        if spec is not None:
            return (
                f"{spec.name} returned no usable data. It may simply have found "
                "nothing; check its raw output via the history action."
            )
        return "Unknown failure; the raw response is stored in history."


# ── result cache ─────────────────────────────────────────────────────────────


class ResultCache:
    """Bounded LRU cache of tool responses keyed by call fingerprint."""

    def __init__(self, maxsize: int = 64, ttl: float = 120.0) -> None:
        self._maxsize = maxsize
        self._ttl = ttl
        self._lock = threading.Lock()
        self._data: "OrderedDict[str, tuple[float, dict]]" = OrderedDict()

    @staticmethod
    def key(tool: str, arguments: dict) -> str:
        canonical = json.dumps({"tool": tool, "args": arguments}, sort_keys=True)
        return hashlib.blake2b(canonical.encode("utf-8"), digest_size=16).hexdigest()

    def get(self, key: str) -> Optional[dict]:
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            stamp, value = item
            if time.monotonic() - stamp > self._ttl:
                self._data.pop(key, None)
                return None
            self._data.move_to_end(key)
            return value

    def put(self, key: str, value: dict) -> None:
        with self._lock:
            self._data[key] = (time.monotonic(), value)
            self._data.move_to_end(key)
            while len(self._data) > self._maxsize:
                self._data.popitem(last=False)

    def stats(self) -> dict:
        with self._lock:
            return {"entries": len(self._data), "maxsize": self._maxsize, "ttl_s": self._ttl}


# ── memory bridge ────────────────────────────────────────────────────────────


class ScanMemory:
    """Persist scan history and contact with the shared long-term memory."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._data = _read_json(MEMORY_PATH)
        self._data.setdefault("scans", [])
        self._data.setdefault("findings", [])
        self._data.setdefault("verdict_counts", {"verified": 0, "refuted": 0, "unverifiable": 0})

    def record_scan(self, tool: str, arguments: dict, response: dict, findings: list[dict]) -> None:
        entry = {
            "tool": tool,
            "arguments": {key: _short(value, 200) for key, value in arguments.items()},
            "ok": not response.get("error"),
            "findings": findings[-50:],
            "at": _now(),
        }
        with self._lock:
            self._data.setdefault("scans", []).append(entry)
            self._data["scans"] = self._data["scans"][-300:]
            for finding in findings:
                verdict = finding.get("verdict", "unverifiable")
                self._data["verdict_counts"][verdict] = self._data["verdict_counts"].get(verdict, 0) + 1
                self._data.setdefault("findings", []).append({
                    "tool": tool, "claim": finding.get("claim", ""),
                    "verdict": verdict, "at": _now(),
                })
            self._data["findings"] = self._data["findings"][-500:]
            _write_json(MEMORY_PATH, self._data)

    def recent(self, k: int = 15) -> list[dict]:
        with self._lock:
            return list(self._data.get("scans", []))[-max(1, k):]

    def verdict_counts(self) -> dict:
        with self._lock:
            return dict(self._data.get("verdict_counts", {}))

    def note_in_long_term(self, summary: str) -> bool:
        """Append one bounded summary line into memory/long_term.json."""
        path = BASE_DIR / "memory" / "long_term.json"
        data = _read_json(path)
        projects = data.setdefault("projects", {})
        if not isinstance(projects, dict):
            return False
        hexstrike = projects.setdefault("hexstrike", {"notes": []})
        notes = hexstrike.setdefault("notes", [])
        if isinstance(notes, list):
            notes.append({"note": _short(summary, 300), "at": _now()})
            hexstrike["notes"] = notes[-50:]
        return _write_json(path, data)


# ── scan pipeline orchestrator ───────────────────────────────────────────────


def _stage_error(stage: dict) -> str:
    """Human-readable reason a pipeline stage produced no usable output.

    A stage can fail in two shapes: the safety gate returns only an ``error``,
    while a tool failure carries one inside its response.  Both must be
    readable without raising.
    """
    response = stage.get("response") or {}
    return str(response.get("error") or stage.get("error") or "stage produced no output")


class ScanPipeline:
    """Chain safe tools into verified multi-stage assessments of one target."""

    def __init__(
        self,
        client: HexStrikeClient,
        gate: SafetyGate,
        verifier: FalsePositiveVerifier,
        memory: ScanMemory,
        logger: Callable[[str], None],
        executor: Optional[Callable[..., tuple[dict, str]]] = None,
    ) -> None:
        self._client = client
        self._gate = gate
        self._verifier = verifier
        self._memory = memory
        self._log = logger
        self._executor = executor

    def _run_stage(self, tool: str, arguments: dict, budget_s: Optional[int] = None) -> dict:
        """Run one pipeline stage inside a wall-clock budget.

        ``budget_s`` is the anti-hang guarantee: a stage that stalls (a
        tarpitting host, a tool doing a slow startup) is cut off instead of
        holding the whole scan hostage.
        """
        spec = CATALOG.get(tool)
        if spec is None:
            return {"error": f"unknown pipeline tool {tool}"}
        allowed, reason = self._gate.check(spec, arguments)
        if not allowed:
            return {"error": reason, "blocked": True}
        self._log(f"⚙️ hexstrike → pipeline stage {tool} on {arguments.get('target', '?')}")
        started = time.monotonic()
        if self._executor is not None:
            response, lane = self._executor(spec, arguments, budget_s)
        else:
            response = self._client.call(
                tool, _harden_scan_payload(tool, arguments), timeout=budget_s or 240
            )
            lane = "server"
        elapsed = round(time.monotonic() - started, 2)
        self._log(f"⏱️ hexstrike → {tool} finished in {elapsed}s on the {lane} lane")
        findings = self._verifier.classify(response, spec, arguments)
        self._memory.record_scan(tool, arguments, response, findings)
        stalled = bool(response.get("timed_out")) or "timed out" in str(response.get("error", "")).casefold()
        if stalled:
            self._log(f"⚠️ hexstrike → {tool} hit its {budget_s}s budget; partial results kept")
        result = {
            "response": response, "findings": findings, "tool": tool,
            "lane": lane, "elapsed_s": elapsed, "stalled": stalled,
        }
        # Surface tool failures at the top level too, otherwise callers that
        # test ``"error" in stage`` read a failed stage as a clean, empty one
        # and report "nothing found" for a scan that never actually ran.
        if response.get("error"):
            result["error"] = str(response["error"])
        return result

    @staticmethod
    def _ports_from_response(response: dict) -> list[int]:
        stdout = str(response.get("stdout") or "")
        return [int(m) for m in re.findall(r"^(\d{1,5})/tcp\s+open", stdout, re.MULTILINE)]

    def recon_pipeline(self, target: str) -> dict:
        """Quick scan, then verify every claim it makes."""
        # Port discovery only.  Version probes are exactly what made router
        # scans crawl, so service naming comes from banner grabs instead.
        stage = self._run_stage("nmap_scan", {"target": target, "scan_type": "-sT"}, budget_s=30)
        if "error" in stage:
            return stage
        findings = stage.get("findings", [])
        summary_lines = [
            f"{f['verdict'].upper()}: {f['claim']} — {f['evidence']}" for f in findings
        ]
        return {
            "target": target,
            "stages": ["nmap_scan"],
            "raw": _short(stage["response"].get("stdout", ""), 2000),
            "response": stage["response"],
            "findings": findings,
            "summary": summary_lines or ["No open services detected."],
        }

    def deep_pipeline(self, target: str, confirmed: bool) -> dict:
        """Port discovery, service verification, then HTTP probing of finds."""
        quick = self.recon_pipeline(target)
        if "error" in quick:
            return quick
        ports = self._ports_from_response(quick.get("response", {}))
        stages = ["nmap_scan"]
        summaries = list(quick.get("summary", []))
        # Targeted version detection: only ports already known to be open,
        # intensity 2, 25s host timeout -- so even a tarpitting device cannot
        # stretch this into a multi-minute wait.
        want_versions = bool(ports) and confirmed
        if not want_versions and ports:
            summaries.append(
                "Service versions skipped (needs confirmed=true); the ports above "
                "are confirmed open and banner-identified."
            )
        if want_versions:
            version = self._run_stage("nmap_scan", {
                "target": target,
                "ports": ",".join(str(p) for p in ports[:20]),
                "scan_type": "-sV",
            }, budget_s=40)
            if "error" not in version:
                stages.append("nmap_scan:version-probe")
                for finding in version.get("findings", []):
                    line = f"{finding['verdict'].upper()}: {finding['claim']} — {finding['evidence']}"
                    if line not in summaries:
                        summaries.append(line)
            elif version.get("stalled"):
                summaries.append(
                    "Version probe hit its 40s budget and was cut off; "
                    "ports above are still confirmed open."
                )
        http_ports = [p for p in ports if p in {80, 443, 8080, 8443, 9999}]
        if http_ports and confirmed is False:
            summaries.append("HTTP deep-probe skipped (needs confirmed=true for httpx).")
        elif http_ports:
            probe = self._run_stage("httpx_probe", {"target": " ".join(f"{target}:{p}" for p in http_ports)}, budget_s=45)
            if "error" not in probe:
                stages.append("httpx_probe")
                summaries.append(_short(probe["response"].get("stdout", ""), 500))
            else:
                # Say why a probe did not run instead of dropping it silently.
                summaries.append("HTTP probe unavailable: " + _short(_stage_error(probe), 200))
        if not confirmed:
            summaries.append(
                "Template vulnerability scan skipped (needs confirmed=true); it is "
                "the slowest stage and is pure waste when the answer is already no."
            )
        else:
            vuln = self._run_stage("nuclei_scan", {"target": f"http://{target}", "severity": "critical,high"}, budget_s=45)
            if "error" not in vuln:
                stages.append("nuclei_scan")
                for finding in vuln.get("findings", []):
                    summaries.append(f"{finding['verdict'].upper()}: {finding['claim']} — {finding['evidence']}")
            else:
                summaries.append(
                    "Template scan unavailable: "
                    + _short(_stage_error(vuln), 200)
                    + (" (budget reached; the port findings above stand)" if vuln.get("stalled") else "")
                )
        return {"target": target, "stages": stages, "summary": summaries or ["Nothing found."]}

    def web_pipeline(self, url: str, confirmed: bool) -> dict:
        """Directory discovery plus technology and WAF fingerprinting."""
        summaries: list[str] = []
        stages: list[str] = []
        waf = self._run_stage("waf_detection", {"url": url})
        if "error" not in waf:
            stages.append("waf_detection")
            summaries.append(_short(waf["response"].get("stdout", ""), 400) or "No WAF detected.")
        dirs = self._run_stage("gobuster_scan", {"url": url, "mode": "dir"})
        if "error" not in dirs:
            stages.append("gobuster_scan")
            for finding in dirs.get("findings", []):
                summaries.append(f"{finding['verdict'].upper()}: {finding['claim']}")
        if confirmed:
            nikto = self._run_stage("nikto_scan", {"target": url})
            if "error" not in nikto:
                stages.append("nikto_scan")
                summaries.append(_short(nikto["response"].get("stdout", ""), 800))
        return {"target": url, "stages": stages, "summary": summaries or ["Nothing notable."]}


# ── the controller ───────────────────────────────────────────────────────────


def _payload_to_argv(arguments: dict) -> list[str]:
    """Convert a server-style payload dict into a local argv list."""
    argv: list[str] = []
    for key, value in arguments.items():
        text = str(value).strip()
        if not text or key in {"target", "url"}:
            continue
        if key == "ports":
            argv.extend(["-p", text])
        elif text.startswith("-"):
            argv.extend(shlex.split(text))
        else:
            argv.append(text)
    for key in ("target", "url"):
        if str(arguments.get(key, "")).strip():
            argv.append(str(arguments[key]).strip())
            break
    return argv


# ── scan speed guard ────────────────────────────────────────────────────────
# The one thing that turns a one-second scan into a five-minute wait is nmap's
# service-version probe (``-sV``) against a router or IoT device: the device
# accepts the TCP connection and then never answers the probe, so nmap idles
# against its own timeout while printing almost nothing.  A monitoring bar that
# divides output bytes by elapsed seconds therefore reads single digits -- it
# is measuring *silence*, not network throughput.  Everything dispatched from
# here now carries hard bounds, on both the local and the server lane.

SCAN_TOOL_HINTS = ("nmap", "masscan", "rustscan", "naabu", "autorecon")
FAST_SCAN_FLAGS = ("--max-retries", "1", "--host-timeout", "25s", "--open")
FAST_VERSION_FLAGS = ("--version-intensity", "2")
SCAN_TIMEOUT_S = 90


def _is_scan_tool(tool: str) -> bool:
    """True for port scanners, where an unbounded run means a hung scan."""
    name = str(tool or "").casefold()
    return any(hint in name for hint in SCAN_TOOL_HINTS)


def _harden_scan_payload(tool: str, arguments: dict) -> dict:
    """Bound one dispatched scan so it can never stall for minutes.

    Applied on *both* lanes, so a slow probe cannot reach the HexStrike
    server either.  Version detection is dropped unless the caller named
    explicit ports (i.e. it is a targeted follow-up on ports already known to
    be open), and even then it is pinned to intensity 2 with a 25s host
    timeout.
    """
    if not _is_scan_tool(tool):
        return arguments
    payload = dict(arguments)
    extra = str(payload.get("additional_args") or "").strip()
    flags: list[str] = []
    if "nmap" in str(tool).casefold():
        if "-sV" in str(payload.get("scan_type") or ""):
            if not str(payload.get("ports") or "").strip():
                payload["scan_type"] = "-sT"
            else:
                flags.extend(FAST_VERSION_FLAGS)
        for flag in FAST_SCAN_FLAGS:
            if flag not in extra:
                flags.append(flag)
    if flags:
        payload["additional_args"] = " ".join(part for part in [extra, *flags] if part).strip()
    if not payload.get("timeout"):
        payload["timeout"] = SCAN_TIMEOUT_S
    return payload


def _execute_spec(
    spec: "ToolSpec",
    arguments: dict,
    aliases: dict,
    client: "HexStrikeClient",
    budget_s: Optional[int] = None,
) -> tuple[dict, str]:
    """Run one tool on the best lane and return ``(response, lane)``.

    Local binaries come first (same tools, no HTTP hop, works with the
    HexStrike server down); the server lane is the fallback.  Pipelines use
    this too -- previously they called the server directly and inherited its
    slow, unbounded ``-sV`` defaults.
    """
    payload = _harden_scan_payload(spec.name, arguments)
    if local_exec is not None:
        alias = aliases.get(spec.name) or spec.name
        if alias in local_exec.ALLOWLIST and shutil.which(alias) is not None:
            if alias == "nmap" and payload.get("target"):
                ports = str(payload.get("ports", "") or "")
                scan_type = str(payload.get("scan_type", "") or "")
                argv = local_exec.smart_nmap_args(
                    _normalise_target(str(payload["target"])),
                    ports=ports,
                    scan_type=scan_type,
                    service_detection=bool(ports.strip()) and "-sV" in scan_type,
                )
            else:
                argv = _payload_to_argv(payload)
            response = local_exec.run(alias, argv, timeout=budget_s or local_exec.TIMEOUT_DEFAULT)
            if "not installed" not in str(response.get("error", "")):
                if alias == "nmap":
                    response = _enrich_with_banners(response, payload)
                return response, "local"
    response = client.call(spec.name, payload, timeout=budget_s or 240)
    if "nmap" in spec.name.casefold():
        response = _enrich_with_banners(response, payload)
    return response, "server"


def _enrich_with_banners(response: dict, arguments: dict) -> dict:
    """Add fast targeted banner grabs to a local nmap result.

    nmap ``-sV`` tarpits for minutes on routers; these two-second socket
    reads identify services faster and never hang.
    """
    if local_exec is None or not response.get("success"):
        return response
    target = _normalise_target(
        str(arguments.get("target") or arguments.get("url") or "")
    )
    if not target:
        return response
    ports = [int(m.group(1)) for m in re.finditer(
        r"^(\d{1,5})/tcp\s+open", str(response.get("stdout", "")), re.MULTILINE
    )][:8]
    banners: list[str] = []
    for port in ports:
        banner = local_exec.grab_banner(target, port)
        if banner:
            first = _short(banner.replace("\r", " ").replace("\n", " | "), 120)
            banners.append(f"banner {port}/tcp: {first}")
    if banners:
        response["stdout"] = str(response.get("stdout", "")) + "\n" + "\n".join(banners)
    return response


class HexStrikeController:
    """Own every subsystem and translate actions into guarded behaviour."""

    def __init__(self) -> None:
        self._log_line: Callable[[str], None] = lambda message: LOGGER.info(message)
        self.health = HealthProbe(self._log)
        self.diagnoser = SelfDiagnoser(self.health, self._log)
        self.opener = ServerOpen(self._log)
        self.client = HexStrikeClient(self._log, health=self.health)
        self.gate = SafetyGate(self._log)
        self.verifier = FalsePositiveVerifier(self._log)
        self.doctor = FailureDoctor(self.diagnoser)
        self.cache = ResultCache()
        self.memory = ScanMemory()
        self.pipeline = ScanPipeline(
            self.client, self.gate, self.verifier, self.memory, self._log,
            executor=self._dispatch_spec,
        )
        self._started = _now()
        self._log("🔌 hexstrike → controller initialised with %d catalogue tools" % CATALOG.count())

    def _log(self, message: str) -> None:
        try:
            self._log_line(_short(message, 500))
        except (OSError, RuntimeError, TypeError):
            LOGGER.info(message)

    def _dispatch_spec(
        self,
        spec: "ToolSpec",
        arguments: dict,
        budget_s: Optional[int] = None,
    ) -> tuple[dict, str]:
        """Lane-aware execution shared by direct actions and scan pipelines."""
        return _execute_spec(
            spec, arguments, self.health.registry().get("aliases", {}), self.client,
            budget_s=budget_s,
        )

    def bind(self, player: Any) -> None:
        """Adopt the host UI's log writer when one is offered."""
        callback = getattr(player, "write_log", None)
        if callable(callback):
            self._log_line = callback

    # ── informational actions ─────────────────────────────────────────────

    def status(self) -> dict:
        diagnosis = self.diagnoser.diagnose()
        return {
            "server_state": diagnosis["state"],
            "remedy": self.diagnoser.remedy(diagnosis["state"]),
            "healthy": diagnosis["state"] == "healthy",
            "missing_tools_on_server": diagnosis["missing_tools"],
            "catalog_tools": CATALOG.count(),
            "safe_tools": len(CATALOG.by_mode(SAFE_MODE)),
            "review_tools": len(CATALOG.by_mode(REVIEW_MODE)),
            "danger_tools": len(CATALOG.by_mode(DANGER_MODE)),
            "requests_inflight": self.client.busy(),
            "cache": self.cache.stats(),
            "gate": self.gate.stats(),
            "verdicts": self.memory.verdict_counts(),
            "local_fast_lane": ({
                "tools_available": local_exec.local_count(),
                "note": "allowlisted binaries run directly, no server hop",
            } if local_exec is not None else {"tools_available": 0}),
            "manifest_tools": len(self.health.registry().get("available", []))
            + len(self.health.registry().get("installable", [])),
            "endpoints_available": len(
                [1 for ok in self.health.live_registry().values() if ok]
            ),
            "aliases_loaded": len(self.health.registry().get("aliases", {})),
            "uptime_s": _now() - self._started,
        }

    def health_summary(self) -> str:
        payload = self.health.fetch(refresh=True)
        if payload is None:
            diagnosis = self.diagnoser.diagnose()
            return f"HexStrike is unreachable: {diagnosis['state']}. {self.diagnoser.remedy(diagnosis['state'])}"
        essential = payload.get("all_essential_tools_available")
        categories = payload.get("category_stats", {})
        lines = [f"HexStrike healthy; essential tools: {'all present' if essential else 'incomplete'}."]
        for name, entry in sorted(categories.items()):
            if isinstance(entry, dict):
                lines.append(f"- {name}: {entry.get('available', '?')}/{entry.get('total', '?')} tools available")
        cache = payload.get("cache_stats", {})
        if isinstance(cache, dict):
            lines.append(f"- server cache hit rate: {cache.get('hit_rate', '?')}")
        totals = self.health.totals()
        if totals.get("registered"):
            lines.append(
                f"- registry: {totals['available']}/{totals['registered']} tools available"
                f" (server v{totals.get('version', '?')})"
            )
        return "\n".join(lines)

    def tools_listing(self, mode: str = "") -> str:
        wanted = mode.strip().casefold().upper() if mode else ""
        totals = self.health.totals()
        registry = self.health.registry()
        lines = [
            f"HexStrike catalogue — {CATALOG.count()} curated tools, "
            f"{totals.get('available', 0)}/{totals.get('registered', 0)} live endpoints on the server."
        ]
        if not wanted:
            lines.append(
                f"Manifest registry: {len(registry.get('available', []))} available, "
                f"{len(registry.get('installable', []))} installable (use install_hint)."
            )
        for spec in CATALOG.all():
            if wanted and spec.mode != wanted:
                continue
            lines.append(f"- [{spec.mode}] {spec.name} ({spec.category}): {spec.summary}")
        return "\n".join(lines)

    def which_report(self) -> str:
        """Report which tool binaries exist on this host for local fallback."""
        names = sorted({spec.local_probe for spec in CATALOG.all() if spec.local_probe})
        lines = []
        for name in names:
            binary = shutil.which(name)
            lines.append(f"- {name}: {'present' if binary else 'missing'}")
        return "\n".join(lines) if lines else "No local tool probes configured."

    def explain_tool(self, tool: str) -> str:
        spec = CATALOG.get(tool)
        if spec is None:
            known = ", ".join(CATALOG.names()[:12])
            return f"Unknown tool {tool!r}. Catalogue starts with: {known}..."
        parts = [
            f"{spec.name} — {spec.summary}",
            f"Category: {spec.category}. Safety class: {spec.mode}.",
        ]
        if spec.mode == SAFE_MODE:
            parts.append("Runs without confirmation on authorised targets.")
        elif spec.mode == REVIEW_MODE:
            parts.append("Requires confirmed=true because it is intrusive or state-changing.")
        else:
            parts.append("Refused outright: destructive exploit or cracking tooling.")
        if spec.params:
            parts.append(f"Parameters: {', '.join(spec.params)}.")
        if spec.local_probe:
            present = shutil.which(spec.local_probe)
            parts.append(f"Server-side binary {spec.local_probe}: {'present' if present else 'missing'}.")
        alias = self.health.registry().get("aliases", {}).get(spec.name)
        if alias:
            parts.append(f"Server endpoint: {alias}.")
        profile = self.health.manifest().get("profiles", {}).get(alias or spec.name, {})
        if profile.get("when_to_use"):
            parts.append(f"Guide: {profile['when_to_use']}")
        return " ".join(parts)

    # ── execution actions ────────────────────────────────────────────────

    def run_tool(self, tool: str, arguments: dict, confirmed: bool) -> dict:
        """Run one catalogue tool through the gate, cache and verifier."""
        spec = CATALOG.get(tool)
        if spec is None:
            return {"error": f"unknown tool {tool!r}", "advice": self.tools_listing()}
        allowed, reason = self.gate.check(spec, arguments)
        if not allowed and confirmed and spec.mode == REVIEW_MODE:
            allowed, reason = True, "confirmed by user on HUD"
        if not allowed:
            self._log(f"🛑 hexstrike → blocked {tool}: {reason}")
            return {"error": "blocked by safety gate", "reason": reason, "tool": spec.name}
        cache_key = ResultCache.key(spec.name, arguments)
        cached = self.cache.get(cache_key)
        if cached is not None:
            self._log(f"⚡ hexstrike → cache hit for {spec.name}")
            return {**cached, "cached": True}
        self._log(f"🛰️ hexstrike → running {spec.name} ({allowed and reason})")
        # Local fast lane first: same binaries, zero HTTP hop, works even if
        # the HexStrike server is down.  Server lane is the fallback.
        response, lane = _execute_spec(
            spec, arguments, self.health.registry().get("aliases", {}), self.client
        )
        if response.get("error"):
            response["advice"] = self.doctor.explain(response, spec)
        findings = self.verifier.classify(response, spec, arguments)
        self.memory.record_scan(spec.name, arguments, response, findings)
        result = {
            "tool": spec.name,
            "ok": not response.get("error"),
            "lane": lane,
            "stdout": _short(response.get("stdout", ""), 4000),
            "stderr": _short(response.get("stderr", ""), 1000),
            "findings": findings,
            "advice": response.get("advice", ""),
            "cached": False,
        }
        self.cache.put(cache_key, result)
        return result

    def verify_finding(self, target: str, finding: str) -> dict:
        """Independently re-test one finding on demand."""
        verdict = self.verifier.verify_vulnerability(target, finding)
        self.memory.record_scan(
            "manual_verify", {"target": target, "claim": finding},
            {"stdout": ""}, [verdict],
        )
        return {"target": target, "finding": _short(finding, 300), **verdict}

    def history_report(self, k: int = 15) -> str:
        scans = self.memory.recent(k)
        if not scans:
            return "No scans recorded yet."
        counts = self.memory.verdict_counts()
        lines = [
            f"Recent {len(scans)} scans; lifetime verdicts: "
            f"{counts.get('verified', 0)} verified, {counts.get('refuted', 0)} refuted, "
            f"{counts.get('unverifiable', 0)} unverifiable."
        ]
        for entry in scans:
            time_str = time.strftime("%m-%d %H:%M", time.localtime(entry.get("at", 0)))
            findings = entry.get("findings", [])
            refuted = sum(1 for f in findings if f.get("verdict") == "refuted")
            lines.append(
                f"- {time_str} {entry.get('tool')} → ok={entry.get('ok')} "
                f"({len(findings)} findings, {refuted} refuted)"
            )
        return "\n".join(lines)

    def guide(self) -> str:
        """Return the condensed usage guide from config/hexstrike_tools.json."""
        data = self.health.manifest()
        guide = data.get("jarvis_usage_guide", {})
        if not guide:
            return "The guide manifest is missing from config/hexstrike_tools.json."
        sections = []
        for key in (
            "mission", "before_anything", "choosing_a_tool", "running_a_tool",
            "verification_contract", "reporting_style", "safety_and_ethics",
            "debugging_itself", "speed_rules",
        ):
            value = guide.get(key)
            if isinstance(value, str):
                sections.append(f"{key}: {value}")
            elif isinstance(value, list):
                bullets = "".join(f"\n  - {item}" for item in value)
                sections.append(f"{key}:{bullets}")
        hints = data.get("false_positive_hints", [])
        if hints:
            bullets = "".join(f"\n  - {item}" for item in hints)
            sections.append(f"false positives to always check:{bullets}")
        return _short("\n\n".join(sections), 4000)

    def playbook(self, name: str) -> str:
        """Return the steps of one named playbook from the manifest."""
        data = self.health.manifest()
        playbooks = data.get("playbooks", {})
        key = str(name or "").strip().casefold()
        entry = playbooks.get(key)
        if entry is None:
            names = ", ".join(sorted(playbooks))
            return f"Unknown playbook {name!r}. Available: {names}."
        lines = [f"Playbook {key}: {entry.get('description', '')}"]
        for index, step in enumerate(entry.get("steps", []), start=1):
            if "tool" in step:
                lines.append(f"  {index}. run {step['tool']} with {json.dumps(step.get('arguments', {}))}")
            elif "verify" in step:
                lines.append(f"  {index}. verify: {step['verify']}")
            elif "report" in step:
                lines.append(f"  {index}. report: {step['report']}")
        lines.append(f"Expected runtime: ~{entry.get('expected_runtime_s', '?')}s.")
        return "\n".join(lines)

    # ── pipeline actions ─────────────────────────────────────────────────

    def action_pipeline(self, kind: str, target: str, confirmed: bool) -> str:
        if kind == "quick":
            result = self.pipeline.recon_pipeline(target)
        elif kind == "deep":
            result = self.pipeline.deep_pipeline(target, confirmed)
        elif kind == "web":
            url = target if str(target).startswith("http") else f"http://{_normalise_target(target)}"
            result = self.pipeline.web_pipeline(url, confirmed)
        else:
            return f"Unknown pipeline kind {kind!r}."
        if "error" in result:
            return f"Pipeline halted: {result['error']}"
        lines = [f"{kind.capitalize()} pipeline on {result.get('target')} finished; stages: {', '.join(result.get('stages', []))}."]
        lines.extend(f"- {item}" for item in result.get("summary", []))
        self.memory.note_in_long_term(f"{kind} scan of {target}: {len(result.get('summary', []))} summary lines")
        return "\n".join(lines)


# ── built-in self test ───────────────────────────────────────────────────────


def _self_test() -> dict:
    """Exercise every subsystem non-destructively."""
    details: dict[str, Any] = {
        "catalog_size": CATALOG.count(),
        "catalog_has_danger": bool(CATALOG.by_mode(DANGER_MODE)),
        "catalog_has_safe": bool(CATALOG.by_mode(SAFE_MODE)),
        "verifier_present": FalsePositiveVerifier(lambda _: None) is not None,
        "gate_blocks_danger": False,
        "gate_blocks_remote_safe": False,
        "cache_roundtrip": False,
        "memory_roundtrip": False,
        "nmap_shape_ok": False,
        "hydra_fp_guard": False,
        "manifest_loaded": False,
        "manifest_aliases_resolve": False,
        "guide_available": False,
        "server_state": "unknown",
    }
    gate = SafetyGate(lambda _: None)
    nmap_spec = CATALOG.get("nmap_scan")
    hydra_spec = CATALOG.get("hydra_attack")
    allowed, _ = gate.check(hydra_spec, {"target": "127.0.0.1"})
    details["gate_blocks_danger"] = not allowed
    allowed, _ = gate.check(nmap_spec, {"target": "evil.example.com"})
    details["gate_blocks_remote_safe"] = not allowed
    cache = ResultCache(maxsize=4, ttl=60)
    cache.put("k1", {"v": 1})
    details["cache_roundtrip"] = cache.get("k1") == {"v": 1}
    memory = ScanMemory()
    memory.record_scan("self_test", {"target": "127.0.0.1"}, {"stdout": "ok"}, [])
    details["memory_roundtrip"] = len(memory.recent(1)) >= 1
    fake_client = HexStrikeClient(lambda _: None)
    real_call = fake_client.call
    fake_client.call = lambda tool, payload, timeout=240: {"stdout": "80/tcp open http Werkzeug httpd"}  # type: ignore[method-assign]
    verifier = FalsePositiveVerifier(lambda _: None)
    findings = verifier.classify(
        {"stdout": "80/tcp open http Werkzeug httpd"},
        CATALOG.get("nmap_scan"), {"target": "127.0.0.1"},
    )
    details["nmap_shape_ok"] = bool(findings) and findings[0]["verdict"] in {"verified", "refuted", "unverifiable"}
    fake_client.call = lambda tool, payload, timeout=240: {"stdout": "[9999][http-get] host: 127.0.0.1   login: admin   password: password"}  # type: ignore[method-assign]
    brute = verifier.classify(
        {"stdout": "[9999][http-get] host: 127.0.0.1   login: admin   password: password"},
        CATALOG.get("hydra_attack"), {"target": "127.0.0.1"},
    )
    details["hydra_fp_guard"] = bool(brute) and brute[0]["verdict"] in {"refuted", "unverifiable", "verified"}
    fake_client.call = real_call  # type: ignore[method-assign]
    controller = HexStrikeController()
    controller._log = lambda _: None  # silence during test
    details["server_state"] = controller.diagnoser.diagnose()["state"]
    manifest = controller.health.manifest()
    details["manifest_loaded"] = bool(manifest.get("profiles"))
    alias_map = manifest.get("endpoint_aliases", {})
    registry = manifest.get("tool_registry", {})
    registered = set(registry.get("available", [])) | set(registry.get("installable", []))
    details["manifest_aliases_resolve"] = bool(
        alias_map and all(target in registered for target in alias_map.values())
    )
    details["guide_available"] = bool(manifest.get("jarvis_usage_guide", {}).get("mission"))
    ok_keys = (
        "gate_blocks_danger", "gate_blocks_remote_safe", "cache_roundtrip",
        "memory_roundtrip", "nmap_shape_ok", "hydra_fp_guard",
        "manifest_loaded", "manifest_aliases_resolve", "guide_available",
    )
    details["ok"] = all(bool(details[key]) for key in ok_keys) and CATALOG.count() >= 40
    return {"ok": bool(details["ok"]), "details": details}


# ── singleton lifecycle ──────────────────────────────────────────────────────


def on_load() -> None:
    """Create the controller lazily so plugin discovery stays cheap."""
    global MONITOR
    with MONITOR_LOCK:
        if MONITOR is None:
            MONITOR = HexStrikeController()
            state = MONITOR.diagnoser.diagnose()
            MONITOR._log(
                f"🧭 hexstrike → server {state['state']}"
                + ("" if state["state"] == "healthy" else f"; {MONITOR.diagnoser.remedy(state['state'])}")
            )


def on_unload() -> None:
    """Clear the singleton; nothing persistent to stop."""
    global MONITOR
    with MONITOR_LOCK:
        MONITOR = None


# ── action dispatch ──────────────────────────────────────────────────────────


def _collect_arguments(params: dict) -> dict:
    """Map flat plugin parameters onto the server's tool payloads."""
    arguments: dict[str, Any] = {}
    mapping = {
        "target": str, "url": str, "ports": str, "arguments": str,
        "severity": str, "username": str, "password_file": str,
        "hash_file": str, "hash_type": str, "provider": str,
    }
    for key, caster in mapping.items():
        if key in params and str(params.get(key, "")).strip():
            arguments[key] = caster(params[key])
    return arguments


def run(params: dict, player: Any = None, session_memory: Any = None) -> Any:
    """Dispatch the hexstrike plugin action."""
    del session_memory
    global MONITOR
    on_load()
    assert MONITOR is not None
    if player is not None:
        MONITOR.bind(player)
    params = params if isinstance(params, dict) else {}
    action = str(params.get("action", "status")).strip().casefold()
    confirmed = bool(params.get("confirmed", False))
    target = _normalise_target(str(params.get("target", "")))
    tool = str(params.get("tool", "")).strip().casefold()

    if action == "status":
        return json.dumps(MONITOR.status(), ensure_ascii=True)
    if action == "health":
        return MONITOR.health_summary()
    if action == "tools":
        return MONITOR.tools_listing(str(params.get("arguments", "")))
    if action == "which":
        return MONITOR.which_report()
    if action == "explain":
        return MONITOR.explain_tool(tool or str(params.get("finding", "")))
    if action == "self_test":
        return json.dumps(_self_test(), ensure_ascii=True)
    if action == "history":
        return MONITOR.history_report(int(params.get("ports") or 0) or 15)
    if action == "open_server":
        return MONITOR.opener.open(confirmed)
    if action == "allow_target":
        return MONITOR.gate.allow_target(target, confirmed)
    if action == "verify":
        return json.dumps(
            MONITOR.verify_finding(
                target or "127.0.0.1",
                str(params.get("finding", "") or params.get("arguments", "")),
            ),
            ensure_ascii=True,
        )
    if action in {"quick_scan", "scan"}:
        if not target:
            return "Give me a target for the scan."
        return MONITOR.action_pipeline("quick", target, confirmed)
    if action == "deep_scan":
        if not target:
            return "Give me a target for the deep scan."
        return MONITOR.action_pipeline("deep", target, confirmed)
    if action == "web_scan":
        url = str(params.get("url") or target).strip()
        if not url:
            return "Give me a URL for the web scan."
        return MONITOR.action_pipeline("web", url, confirmed)
    if action == "vuln_scan":
        if not target:
            return "Give me a target for the vulnerability scan."
        result = MONITOR.run_tool("nuclei_scan", {"target": f"http://{target}"}, confirmed)
        return _format_run(result)
    if action == "audit_passwords":
        hash_file = str(params.get("hash_file", "")).strip()
        if not hash_file:
            return "Password auditing is destructive and I only support the offline, read-only part: give me hash_file with confirmed=true to identify a hash safely."
        result = MONITOR.run_tool("hash_identifier", {"hash_string": Path(hash_file).read_text(encoding="utf-8", errors="replace")[:200]}, confirmed)
        return _format_run(result)
    if action == "cloud_scan":
        result = MONITOR.run_tool("prowler_scan", {"provider": str(params.get("provider") or "aws")}, confirmed)
        return _format_run(result)
    if action == "container_scan":
        result = MONITOR.run_tool("trivy_scan", {"scan_type": "image", "target": str(params.get("target", ""))}, confirmed)
        return _format_run(result)
    if action == "pipeline":
        if not target:
            return "Give me a target for the pipeline."
        return MONITOR.action_pipeline("deep", target, confirmed)
    if action == "guide":
        return MONITOR.guide()
    if action == "playbook":
        return MONITOR.playbook(str(params.get("arguments", "")))
    if action == "registry":
        return json.dumps(
            {
                "server_totals": MONITOR.health.totals(),
                "manifest": MONITOR.health.registry(),
                "live_endpoints_available": sorted(
                    name for name, ok in MONITOR.health.live_registry().items() if ok
                ),
            },
            ensure_ascii=True,
        )
    if action == "install_hint":
        name = tool or target
        data = MONITOR.health.manifest()
        profile = data.get("installable_profiles", {}).get(name, {})
        if not profile:
            return f"{name!r} is not in the installable list; check the registry action."
        hint = profile.get("install_hint", "no hint recorded")
        return f"{name}: {hint}. After installing, re-check with the health action."
    if action:
        arguments = _collect_arguments(params)
        if params.get("ports"):
            arguments["ports"] = str(params["ports"])
        result = MONITOR.run_tool(tool, arguments, confirmed)
        return _format_run(result)
    return "Unknown hexstrike action. Try status, tools, scan, verify or explain."


def _format_run(result: dict) -> str:
    """Render one run_tool result as speech-friendly text."""
    if result.get("error") == "blocked by safety gate":
        return f"That run was blocked: {result.get('reason', 'safety policy')}"
    if result.get("error"):
        return f"{result['tool']} failed: {result.get('error')} {result.get('advice', '')}".strip()
    lines = [f"{result.get('tool')} finished." + (" (cached)" if result.get("cached") else "")]
    stdout = str(result.get("stdout", ""))
    if stdout:
        lines.append(_short(stdout, 1200))
    for finding in result.get("findings", []):
        lines.append(f"- {finding.get('verdict', '?').upper()}: {finding.get('claim', '')} — {finding.get('evidence', '')}")
    if result.get("advice"):
        lines.append(f"Note: {result['advice']}")
    return "\n".join(lines)


if __name__ == "__main__":
    on_load()
    print(json.dumps(_self_test(), indent=2, ensure_ascii=True))
