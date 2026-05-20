#!/usr/bin/env python3
"""
file_triage.py — First-Level Malware Triage Tool  v3.0
═══════════════════════════════════════════════════════
Hashes a file, classifies application type, extracts metadata/strings/IOCs,
performs PE analysis, queries multiple open-source threat intel APIs,
searches NVD/MITRE CVE for known vulnerabilities by application name,
and generates a professional PDF report.

pip install requests pefile colorama tabulate reportlab

API Keys (all free tiers — only MalwareBazaar/URLhaus/ThreatFox/CIRCL need NO key):
  VIRUSTOTAL_API_KEY  → https://www.virustotal.com/gui/sign-in
  OTX_API_KEY         → https://otx.alienvault.com/api
  GREYNOISE_API_KEY   → https://www.greynoise.io  (community tier)

Usage:
  python file_triage.py setup.exe
  python file_triage.py setup.exe --app-name "TeamViewer" --version "15.0"
  python file_triage.py setup.exe --app-name "AnyDesk" --pdf report.pdf
  VIRUSTOTAL_API_KEY=abc OTX_API_KEY=xyz python file_triage.py app.exe --pdf
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Optional

import requests

# ── Graceful optional imports ─────────────────────────────────────────────────
try:
    from colorama import Fore, Style, init as _cinit
    _cinit(autoreset=True)
except ImportError:
    class _Stub:
        def __getattr__(self, _): return ""
    Fore = Style = _Stub()

try:
    from tabulate import tabulate as _tab
    def tabulate(rows, **kw): return _tab(rows, **kw)
except ImportError:
    def tabulate(rows, **kw):
        return "\n".join(f"  {str(r[0]):<30} {r[1]}" for r in rows)

# ─── Configuration ────────────────────────────────────────────────────────────
# ─── .env loader ─────────────────────────────────────────────────────────────
# Loads KEY=VALUE pairs from a .env file in the same directory as this script.
# Environment variables already set take precedence over .env values.
def _load_dotenv():
    env_path = Path(__file__).parent / ".env"
    if not env_path.exists():
        return
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            key = key.strip()
            val = val.strip().strip('"').strip("'").rstrip("$")  # strip shell metachar if accidentally copied
            if key and key not in os.environ:   # env vars take precedence
                os.environ[key] = val

_load_dotenv()

# ─── Configuration ────────────────────────────────────────────────────────────
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
OTX_API_KEY        = os.getenv("OTX_API_KEY", "")
GREYNOISE_API_KEY  = os.getenv("GREYNOISE_API_KEY", "")
REQUEST_TIMEOUT    = 20

# ─── Risk Weights ─────────────────────────────────────────────────────────────
RISK_WEIGHTS = {
    "vt_detections":       10,
    "mb_known_malware":    50,
    "otx_pulses":           5,
    "high_entropy":        20,
    "suspicious_imports":  15,
    "suspicious_strings":   3,
    "urlhaus_hit":         30,
    "threatfox_hit":       35,
    "greynoise_malicious": 25,
    "magic_mismatch":      15,
    "rat_category":        10,
}

# ─── Application Classification ───────────────────────────────────────────────
# Each category: (display_name, risk_note, list_of_keyword_patterns)
APP_CATEGORIES = {
    "remote_access": (
        "Remote Access Tool (RAT / RMM)",
        "HIGH POLICY RISK — Can provide full remote control of endpoint",
        [
            r"teamviewer", r"anydesk", r"logmein", r"gotomypc", r"splashtop",
            r"remotepc", r"vnc|vncviewer|tightvnc|ultravnc|realvnc",
            r"rdp|mstsc|remote\s*desktop",
            r"dameware", r"bomgar|beyondtrust", r"connectwise|screenconnect",
            r"ammyy", r"supremo", r"rustdesk", r"netop",
            r"radmin", r"remoteutilities", r"atera", r"n-able|ncentral",
        ],
    ),
    "session_sharing": (
        "Screen / Session Sharing",
        "MODERATE POLICY RISK — Real-time screen broadcast, may exfiltrate display",
        [
            r"webex|cisco\s*webex", r"zoom", r"teams|microsoft\s*teams",
            r"gotomeeting|gotomypc", r"join\.me", r"skype",
            r"bluejeans", r"ringcentral", r"google\s*meet",
            r"slack\s*huddle", r"screenshare|screen\s*share",
            r"obs\s*studio|xsplit", r"loom",
        ],
    ),
    "database_client": (
        "Database Connection Tool",
        "HIGH DATA RISK — Can access, export, or modify databases",
        [
            r"dbeaver", r"navicat", r"tableplus", r"datagrip", r"sequel\s*pro",
            r"mysql\s*workbench", r"pgadmin|postgresql", r"sql\s*server\s*management",
            r"toad\s*for", r"oracle\s*sql\s*developer",
            r"mongodb\s*compass", r"robo\s*3t|robomongo",
            r"redis\s*desktop|rdm", r"cassandra", r"adminer",
            r"azure\s*data\s*studio", r"beekeeper",
        ],
    ),
    "cloud_collaboration": (
        "Cloud / Collaboration Platform",
        "MODERATE RISK — Cloud sync may transfer sensitive data off-premise",
        [
            r"dropbox", r"box\.net|box\s*drive", r"google\s*drive|googledrivesync",
            r"onedrive|skydrive", r"sharepoint", r"confluence",
            r"notion", r"airtable", r"monday\.com",
            r"asana", r"trello", r"jira", r"basecamp",
            r"slack", r"mattermost", r"discord",
        ],
    ),
    "vpn_tunnel": (
        "VPN / Tunneling Client",
        "HIGH NETWORK RISK — Routes traffic outside corporate perimeter",
        [
            r"nordvpn", r"expressvpn", r"protonvpn", r"surfshark",
            r"mullvad", r"privateinternetaccess|pia\s*vpn",
            r"wireguard", r"openvpn", r"cisco\s*anyconnect",
            r"globalprotect|palo\s*alto", r"fortinet|forticlient",
            r"pulse\s*secure|ivanti", r"tunnelbear", r"hotspot\s*shield",
            r"tor\s*browser|torbrowser", r"ngrok", r"frp\b",
        ],
    ),
    "packet_capture": (
        "Network / Packet Capture Tool",
        "HIGH — Can intercept credentials and network traffic",
        [
            r"wireshark", r"tcpdump", r"nmap", r"netcat|nc\.exe",
            r"fiddler", r"charles\s*proxy", r"burp\s*suite",
            r"metasploit", r"aircrack", r"kismet",
            r"zeek|bro\s*ids", r"scapy", r"ettercap",
        ],
    ),
    "credential_tool": (
        "Credential / Password Tool",
        "CRITICAL — Handles authentication credentials; high abuse potential",
        [
            r"keepass|keepassx", r"1password", r"lastpass", r"bitwarden",
            r"dashlane", r"roboform", r"hashcat", r"john\s*the\s*ripper",
            r"mimikatz", r"lazagne", r"credentialfileview",
            r"nirsoft.*pass", r"passwordfox",
        ],
    ),
    "dev_tool": (
        "Developer / Build Tool",
        "LOW-MODERATE — Legitimate dev use; watch for obfuscated scripts",
        [
            r"visual\s*studio|vscode", r"intellij|pycharm|webstorm|goland",
            r"eclipse", r"netbeans", r"xcode",
            r"git\b|github\s*desktop|sourcetree",
            r"docker\s*desktop", r"vagrant", r"postman",
            r"node\.js|nodejs", r"python.*installer", r"ruby.*installer",
        ],
    ),
    "browser": (
        "Web Browser",
        "LOW — Standard browser; verify it is the official installer",
        [
            r"chrome|chromium", r"firefox|mozilla", r"msedge|microsoft\s*edge",
            r"opera", r"brave\s*browser", r"vivaldi", r"tor\s*browser",
        ],
    ),
}

# ─── PE Suspicious Imports ────────────────────────────────────────────────────
SUSPICIOUS_IMPORTS = {
    "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "ShellExecute", "ShellExecuteEx", "WinExec", "CreateProcess", "CreateProcessA",
    "RegSetValueEx", "RegCreateKey", "RegOpenKey", "RegCreateKeyEx",
    "InternetOpen", "InternetConnect", "HttpSendRequest", "URLDownloadToFile",
    "WSAStartup", "connect", "send", "recv", "WSASend",
    "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptAcquireContext",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
    "SetWindowsHookEx", "GetAsyncKeyState", "GetForegroundWindow",
    "OpenProcess", "TerminateProcess", "SuspendThread",
    "FindFirstFile", "FindNextFile", "DeleteFile",
}

# ─── Suspicious String Patterns ───────────────────────────────────────────────
SUSPICIOUS_PATTERNS = [
    (r"https?://\d{1,3}(\.\d{1,3}){3}[:/]", "IP-based URL"),
    (r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "Raw IP address"),
    (r"cmd\.exe|powershell|wscript\.exe|cscript\.exe", "Shell execution"),
    (r"HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM\\|HKCU\\", "Registry access"),
    (r"\\AppData\\|\\Temp\\|\\System32\\|\\SysWOW64\\", "Sensitive path"),
    (r"base64|b64decode|frombase64string|btoa|atob", "Base64 encoding"),
    (r"\bwget\b|\bcurl\b|Invoke-WebRequest|DownloadFile|DownloadString", "Download utility"),
    (r"mimikatz|sekurlsa|lsadump|wce\.exe", "Credential dumping"),
    (r"\.onion", "Tor hidden service"),
    (r"\bbitcoin\b|\bmonero\b|\bwallet\b|\bcryptowallet\b", "Cryptocurrency"),
    (r"ransom|encrypt.*file|decrypt.*key|YOUR_FILES", "Ransomware keyword"),
    (r"CreateService|StartService|OpenSCManager", "Service manipulation"),
    (r"netsh|ipconfig|arp\s+-a|nslookup|whoami", "Recon command"),
    (r"schtasks|at\.exe|taskschd", "Scheduled task"),
]

# ─── Magic Bytes Map ──────────────────────────────────────────────────────────
MAGIC_SIGNATURES = {
    b"\x4d\x5a":                     "PE/EXE (Windows Executable)",
    b"\x7f\x45\x4c\x46":             "ELF (Linux Executable)",
    b"\xca\xfe\xba\xbe":             "Mach-O (macOS Executable)",
    b"\x50\x4b\x03\x04":             "ZIP Archive",
    b"\x50\x4b\x05\x06":             "ZIP Archive (empty)",
    b"\x52\x61\x72\x21":             "RAR Archive",
    b"\x1f\x8b":                     "GZIP Archive",
    b"\x42\x5a\x68":                 "BZIP2 Archive",
    b"\x25\x50\x44\x46":             "PDF Document",
    b"\xd0\xcf\x11\xe0":             "MS Office (OLE) Document",
    b"\x37\x7a\xbc\xaf\x27\x1c":    "7-Zip Archive",
    b"\x4d\x53\x43\x46":             "Microsoft Cabinet (.cab)",
    b"\xfe\xed\xfa\xce":             "Mach-O 32-bit",
    b"\xfe\xed\xfa\xcf":             "Mach-O 64-bit",
    b"\x23\x21":                     "Script (shebang)",
    b"\x3c\x3f\x78\x6d\x6c":        "XML Document",
    b"\x3c\x68\x74\x6d\x6c":        "HTML Document",
}

# ─── Console Helpers ─────────────────────────────────────────────────────────

def banner():
    print(Fore.CYAN + r"""
  ███████╗██╗██╗     ███████╗    ████████╗██████╗ ██╗ █████╗  ██████╗ ███████╗
  ██╔════╝██║██║     ██╔════╝    ╚══██╔══╝██╔══██╗██║██╔══██╗██╔════╝ ██╔════╝
  █████╗  ██║██║     █████╗         ██║   ██████╔╝██║███████║██║  ███╗█████╗
  ██╔══╝  ██║██║     ██╔══╝         ██║   ██╔══██╗██║██╔══██║██║   ██║██╔══╝
  ██║     ██║███████╗███████╗       ██║   ██║  ██║██║██║  ██║╚██████╔╝███████╗
  ╚═╝     ╚═╝╚══════╝╚══════╝       ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
""" + Style.RESET_ALL)
    print(Fore.YELLOW + "  First-Level Malware Triage + App Classification  |  v2.0\n" + Style.RESET_ALL)


def hdr(title: str):
    print("\n" + Fore.CYAN + "─" * 64)
    print(f"  {title}")
    print("─" * 64 + Style.RESET_ALL)


def risk_label(score: int) -> str:
    if score == 0:   return Fore.GREEN  + f"CLEAN  (score: {score}/100)" + Style.RESET_ALL
    if score < 30:   return Fore.YELLOW + f"LOW    (score: {score}/100)" + Style.RESET_ALL
    if score < 70:   return Fore.MAGENTA+ f"MEDIUM (score: {score}/100)" + Style.RESET_ALL
    return               Fore.RED    + f"HIGH   (score: {score}/100)" + Style.RESET_ALL


# ─── Step 1 · Hashing ────────────────────────────────────────────────────────

def compute_hashes(filepath: str) -> dict:
    hdr("STEP 1 · FILE HASHES")
    algos = {
        "md5":    hashlib.md5(),
        "sha1":   hashlib.sha1(),
        "sha256": hashlib.sha256(),
    }
    with open(filepath, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            for h in algos.values():
                h.update(chunk)
    out = {k: v.hexdigest() for k, v in algos.items()}
    for k, v in out.items():
        print(f"  {Fore.WHITE}{k.upper():<8}{Style.RESET_ALL}  {v}")
    return out


# ─── Step 2 · Metadata + Magic Bytes ─────────────────────────────────────────

def file_metadata(filepath: str) -> dict:
    hdr("STEP 2 · FILE METADATA & MAGIC BYTES")
    stat = os.stat(filepath)
    ext  = Path(filepath).suffix.lower() or "(none)"

    with open(filepath, "rb") as fh:
        header = fh.read(8)

    detected_type = "Unknown"
    for magic, label in MAGIC_SIGNATURES.items():
        if header[:len(magic)] == magic:
            detected_type = label
            break

    # Extension vs magic mismatch check
    ext_map = {
        ".exe": "PE/EXE", ".dll": "PE/EXE", ".msi": "ZIP Archive",
        ".pdf": "PDF", ".zip": "ZIP Archive", ".rar": "RAR",
    }
    expected = ext_map.get(ext, "")
    mismatch = bool(expected and expected not in detected_type)

    meta = {
        "filename":      os.path.basename(filepath),
        "size_bytes":    stat.st_size,
        "size_human":    f"{stat.st_size / 1024:.1f} KB",
        "modified":      datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
        "extension":     ext,
        "detected_type": detected_type,
        "magic_mismatch": mismatch,
    }
    for k, v in meta.items():
        val_str = str(v)
        color = Fore.RED if k == "magic_mismatch" and v else Fore.WHITE
        print(f"  {color}{k:<18}{Style.RESET_ALL}  {val_str}")
    if mismatch:
        print(f"\n  {Fore.RED}⚠  Extension/magic mismatch: extension is {ext} but file looks like {detected_type}{Style.RESET_ALL}")
    return meta


# ─── Step 3 · Application Classification ─────────────────────────────────────

def classify_application(filepath: str) -> dict:
    hdr("STEP 3 · APPLICATION CLASSIFICATION")
    filename  = os.path.basename(filepath).lower()
    result    = {"matches": [], "primary_category": None, "policy_note": ""}

    with open(filepath, "rb") as fh:
        raw_bytes = fh.read(min(1_048_576, os.path.getsize(filepath)))  # first 1 MB
    text = raw_bytes.decode("latin-1").lower()
    search_corpus = filename + "\n" + text

    for cat_key, (display, note, patterns) in APP_CATEGORIES.items():
        for pat in patterns:
            if re.search(pat, search_corpus, re.IGNORECASE):
                result["matches"].append({
                    "key": cat_key, "display": display,
                    "note": note, "matched_pattern": pat,
                })
                break  # one match per category is enough

    if result["matches"]:
        primary = result["matches"][0]
        result["primary_category"] = primary["key"]
        result["policy_note"]      = primary["note"]
        print(f"  {Fore.YELLOW}Application type(s) detected:{Style.RESET_ALL}")
        for m in result["matches"]:
            print(f"\n  {'Category':<16}: {Fore.WHITE}{m['display']}{Style.RESET_ALL}")
            print(f"  {'Policy note':<16}: {Fore.YELLOW}{m['note']}{Style.RESET_ALL}")
    else:
        result["primary_category"] = "unknown"
        result["policy_note"]      = "No specific category matched — generic binary."
        print(f"  {Fore.GREEN}No special application category matched.{Style.RESET_ALL}")
        print("  Classified as: General / Unknown Binary")

    return result


# ─── Step 4 · PE Header Analysis ─────────────────────────────────────────────

def analyze_pe(filepath: str) -> dict:
    hdr("STEP 4 · PE HEADER ANALYSIS")
    result = {"is_pe": False, "imports": [], "suspicious_imports": [], "sections": []}
    try:
        import pefile
    except ImportError:
        print(Fore.YELLOW + "  pefile not installed: pip install pefile" + Style.RESET_ALL)
        return result

    try:
        pe = pefile.PE(filepath)
    except Exception as e:
        msg = str(e).lower()
        if any(x in msg for x in ["not a valid pe", "magic", "dos"]):
            print("  Not a PE/EXE — skipping PE header analysis.")
        else:
            print(Fore.YELLOW + f"  PE parse note: {e}" + Style.RESET_ALL)
        return result

    result["is_pe"]     = True
    result["machine"]   = pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, "Unknown")
    result["compiled"]  = datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat()
    result["subsystem"] = pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, "Unknown")

    # imphash
    try:
        result["imphash"] = pe.get_imphash()
    except Exception:
        result["imphash"] = ""

    print(f"  {'Architecture':<16}: {result['machine']}")
    print(f"  {'Compiled':<16}: {result['compiled']}")
    print(f"  {'Subsystem':<16}: {result['subsystem']}")
    print(f"  {'Imphash':<16}: {result.get('imphash','N/A')}")

    # Sections
    print(f"\n  {'Section':<14} {'Entropy':>8}  Status")
    for sec in pe.sections:
        name    = sec.Name.decode(errors="replace").strip("\x00")
        entropy = sec.get_entropy()
        high    = entropy > 7.0
        result["sections"].append({"name": name, "entropy": round(entropy, 2), "high": high})
        flag = Fore.RED + "⚠ HIGH (packed?)" + Style.RESET_ALL if high else Fore.GREEN + "OK" + Style.RESET_ALL
        print(f"  {name:<14} {entropy:>8.2f}  {flag}")

    # Imports
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    name = imp.name.decode(errors="replace")
                    result["imports"].append(name)
                    if name in SUSPICIOUS_IMPORTS:
                        result["suspicious_imports"].append(name)

    result["suspicious_imports"] = list(dict.fromkeys(result["suspicious_imports"]))  # dedupe
    if result["suspicious_imports"]:
        print(f"\n  {Fore.RED}Suspicious imports ({len(result['suspicious_imports'])}):{Style.RESET_ALL}")
        for imp in result["suspicious_imports"]:
            print(f"    ⚠  {imp}")
    else:
        print(f"\n  {Fore.GREEN}No suspicious imports found.{Style.RESET_ALL}")

    return result


# ─── Step 5 · String + IOC Extraction ────────────────────────────────────────

def extract_strings_and_iocs(filepath: str) -> dict:
    hdr("STEP 5 · SUSPICIOUS STRINGS & IOC EXTRACTION")
    result = {"hits": [], "ips": [], "urls": [], "domains": []}
    with open(filepath, "rb") as fh:
        raw = fh.read()
    text = raw.decode("latin-1")

    for pattern, label in SUSPICIOUS_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            unique = list(dict.fromkeys(str(m[0] if isinstance(m, tuple) else m) for m in matches))[:5]
            result["hits"].append({"label": label, "samples": unique})
            print(f"  {Fore.RED}⚠  {label}{Style.RESET_ALL}")
            for s in unique[:3]:
                print(f"      → {s}")

    # Extract IOCs for later API queries
    result["ips"] = list(dict.fromkeys(
        re.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", text)
    ))[:10]
    result["urls"] = list(dict.fromkeys(
        re.findall(r"https?://[^\s\"'<>]{6,80}", text)
    ))[:10]
    result["domains"] = list(dict.fromkeys(
        re.findall(r"\b(?:[a-zA-Z0-9\-]{2,63}\.)+(?:com|net|org|io|ru|cn|cc|xyz|top|biz)\b", text)
    ))[:10]

    private_nets = re.compile(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.)")
    result["ips"] = [ip for ip in result["ips"] if not private_nets.match(ip)]

    if result["ips"]:
        print(f"\n  {Fore.YELLOW}Extracted IPs for intel lookup:{Style.RESET_ALL} {', '.join(result['ips'][:5])}")
    if result["urls"]:
        print(f"  {Fore.YELLOW}Extracted URLs for intel lookup:{Style.RESET_ALL} {len(result['urls'])} found")
    if not result["hits"]:
        print(f"  {Fore.GREEN}No suspicious string patterns matched.{Style.RESET_ALL}")

    return result


# ─── Step 6 · CIRCL hashlookup ───────────────────────────────────────────────

def query_circl(sha256: str) -> dict:
    hdr("STEP 6 · CIRCL HASHLOOKUP  (known-good check — no key required)")
    result = {"known_good": False, "info": {}}
    try:
        resp = requests.get(
            f"https://hashlookup.circl.lu/lookup/sha256/{sha256}",
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 200:
            data = resp.json()
            result["known_good"] = True
            result["info"] = {
                "product":    data.get("KnownMalicious", data.get("FileName", "N/A")),
                "db_source":  data.get("hashlookup:source", "N/A"),
                "trust":      data.get("hashlookup:trust", "N/A"),
            }
            print(Fore.GREEN + "  ✓ Hash found in CIRCL known-good database!" + Style.RESET_ALL)
            print(f"  Source : {result['info']['db_source']}")
            print(f"  Trust  : {result['info']['trust']}")
            print(f"  File   : {result['info']['product']}")
        elif resp.status_code == 404:
            print(Fore.YELLOW + "  Hash not in CIRCL known-good DB — unknown or new file." + Style.RESET_ALL)
        else:
            print(Fore.YELLOW + f"  CIRCL returned status {resp.status_code}" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.YELLOW + f"  CIRCL error: {e}" + Style.RESET_ALL)
    return result


# ─── Step 7 · VirusTotal ──────────────────────────────────────────────────────

def query_virustotal(sha256: str) -> dict:
    hdr("STEP 7 · VIRUSTOTAL INTEL")
    result = {"checked": False, "detections": 0, "total": 0, "flagging_engines": []}
    if not VIRUSTOTAL_API_KEY:
        print(Fore.YELLOW + "  VIRUSTOTAL_API_KEY not set — skipping." + Style.RESET_ALL)
        return result
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 404:
            print(Fore.YELLOW + "  Hash not in VirusTotal — new or uncommon file." + Style.RESET_ALL)
            return result
        if resp.status_code == 401:
            print(Fore.RED + "  Invalid VirusTotal API key." + Style.RESET_ALL)
            return result
        data  = resp.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        mal   = stats.get("malicious", 0)
        sus   = stats.get("suspicious", 0)
        total = sum(stats.values())
        engines = data["data"]["attributes"].get("last_analysis_results", {})
        flagged = [
            f"{eng}: {v['result']}" for eng, v in engines.items()
            if v.get("category") in ("malicious", "suspicious")
        ][:8]
        result.update({"checked": True, "detections": mal, "total": total,
                        "suspicious": sus, "flagging_engines": flagged, "stats": stats})
        color = Fore.RED if mal > 5 else (Fore.YELLOW if mal > 0 or sus > 0 else Fore.GREEN)
        print(f"  {color}Malicious: {mal}/{total} engines{Style.RESET_ALL}  |  Suspicious: {sus}")
        if flagged:
            print(f"\n  {Fore.RED}Flagging engines:{Style.RESET_ALL}")
            for f in flagged:
                print(f"    ⚠  {f}")
    except Exception as e:
        print(Fore.YELLOW + f"  VirusTotal error: {e}" + Style.RESET_ALL)
    return result


# ─── Step 8 · MalwareBazaar ───────────────────────────────────────────────────

def query_malwarebazaar(sha256: str) -> dict:
    hdr("STEP 8 · MALWAREBAZAAR  (no key required)")
    result = {"found": False, "malware_family": None, "tags": []}
    try:
        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": sha256},
            timeout=REQUEST_TIMEOUT,
        )
        data = resp.json()
        if data.get("query_status") == "hash_not_found":
            print(Fore.GREEN + "  Not in MalwareBazaar — no known malware match." + Style.RESET_ALL)
        elif data.get("query_status") == "ok":
            info = data["data"][0]
            result.update({
                "found":           True,
                "malware_family":  info.get("signature", "Unknown"),
                "tags":            info.get("tags") or [],
                "file_type":       info.get("file_type", ""),
                "first_seen":      info.get("first_seen", ""),
                "reporter":        info.get("reporter", ""),
            })
            print(Fore.RED + "  ⚠  KNOWN MALWARE in MalwareBazaar!" + Style.RESET_ALL)
            print(f"  Family    : {result['malware_family']}")
            print(f"  Tags      : {', '.join(result['tags']) if result['tags'] else 'none'}")
            print(f"  First seen: {result['first_seen']}")
    except Exception as e:
        print(Fore.YELLOW + f"  MalwareBazaar error: {e}" + Style.RESET_ALL)
    return result


# ─── Step 9 · URLhaus ─────────────────────────────────────────────────────────

def query_urlhaus(urls: list) -> dict:
    hdr("STEP 9 · URLHAUS IOC CHECK  (no key required)")
    result = {"hits": [], "checked": 0}
    if not urls:
        print("  No URLs extracted from file — skipping.")
        return result
    for url in urls[:5]:
        try:
            resp = requests.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url},
                timeout=REQUEST_TIMEOUT,
            )
            data = resp.json()
            result["checked"] += 1
            if data.get("query_status") == "is_listed":
                result["hits"].append({
                    "url":         url,
                    "threat":      data.get("threat", "unknown"),
                    "date_added":  data.get("date_added", ""),
                })
                print(Fore.RED + f"  ⚠  MALICIOUS URL: {url[:70]}" + Style.RESET_ALL)
                print(f"     Threat: {data.get('threat','?')}  Added: {data.get('date_added','?')}")
            else:
                print(Fore.GREEN + f"  Clean: {url[:70]}" + Style.RESET_ALL)
            time.sleep(0.5)  # be polite to the API
        except Exception as e:
            print(Fore.YELLOW + f"  URLhaus error for {url[:40]}: {e}" + Style.RESET_ALL)
    if not result["hits"] and result["checked"]:
        print(f"  {Fore.GREEN}All {result['checked']} checked URL(s) appear clean.{Style.RESET_ALL}")
    return result


# ─── Step 10 · ThreatFox ──────────────────────────────────────────────────────

def query_threatfox(sha256: str, ips: list) -> dict:
    hdr("STEP 10 · THREATFOX IOC CHECK  (no key required)")
    result = {"hash_hit": False, "ip_hits": [], "ioc_details": {}}

    # Hash lookup
    try:
        resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_hash", "hash": sha256},
            timeout=REQUEST_TIMEOUT,
        )
        data = resp.json()
        if data.get("query_status") == "ok":
            ioc = data["data"][0]
            result["hash_hit"] = True
            result["ioc_details"] = {
                "malware":       ioc.get("malware_printable", ""),
                "confidence":    ioc.get("confidence_level", ""),
                "first_seen":    ioc.get("first_seen", ""),
                "threat_type":   ioc.get("threat_type", ""),
            }
            print(Fore.RED + "  ⚠  Hash found in ThreatFox IOC database!" + Style.RESET_ALL)
            print(f"  Malware    : {result['ioc_details']['malware']}")
            print(f"  Threat type: {result['ioc_details']['threat_type']}")
            print(f"  Confidence : {result['ioc_details']['confidence']}%")
        else:
            print(Fore.GREEN + "  Hash not in ThreatFox." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.YELLOW + f"  ThreatFox hash error: {e}" + Style.RESET_ALL)

    # IP lookups
    for ip in ips[:3]:
        try:
            resp = requests.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": ip},
                timeout=REQUEST_TIMEOUT,
            )
            data = resp.json()
            if data.get("query_status") == "ok":
                result["ip_hits"].append(ip)
                print(Fore.RED + f"  ⚠  IP in ThreatFox: {ip}" + Style.RESET_ALL)
            time.sleep(0.5)
        except Exception:
            pass

    return result


# ─── Step 11 · AlienVault OTX ────────────────────────────────────────────────

def query_otx(sha256: str) -> dict:
    hdr("STEP 11 · ALIENVAULT OTX INTEL")
    result = {"checked": False, "pulses": 0, "pulse_names": []}
    if not OTX_API_KEY:
        print(Fore.YELLOW + "  OTX_API_KEY not set — skipping." + Style.RESET_ALL)
        return result
    try:
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/file/{sha256}/general",
            headers={"X-OTX-API-KEY": OTX_API_KEY},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 404:
            print(Fore.GREEN + "  No OTX pulses found." + Style.RESET_ALL)
            return result
        data   = resp.json()
        pulses = data.get("pulse_info", {}).get("pulses", [])
        result.update({"checked": True, "pulses": len(pulses),
                        "pulse_names": [p["name"] for p in pulses[:6]]})
        if pulses:
            print(Fore.RED + f"  ⚠  In {len(pulses)} OTX threat pulse(s)!" + Style.RESET_ALL)
            for n in result["pulse_names"]:
                print(f"    • {n}")
        else:
            print(Fore.GREEN + "  No OTX threat pulses." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.YELLOW + f"  OTX error: {e}" + Style.RESET_ALL)
    return result


# ─── Step 12 · MITRE CVE Search ──────────────────────────────────────────────

def query_nvd_cve(app_name: str, version: str = "") -> dict:
    hdr("STEP 12 · CVE SEARCH  (NVD API v2 — last 3 years)")
    result = {"cves": [], "total": 0, "queried": False,
              "app_name": app_name, "version": version}
    if not app_name:
        print("  No --app-name provided — skipping CVE lookup.")
        return result

    result["queried"] = True

    import subprocess, shlex

    current_year = datetime.datetime.now().year
    cutoff_year  = current_year - 3
    cutoff_dt    = datetime.datetime(cutoff_year, 1, 1)
    name         = app_name.strip()
    keyword      = f"{name} {version}".strip() if version else name

    print(f"  App    : {Fore.WHITE}{keyword}{Style.RESET_ALL}")
    print(f"  Since  : {cutoff_year}-01-01")

    out_file = f"/tmp/nvd_{os.getpid()}.json"

    # Exact proven command — run verbatim via shell
    # User confirmed this works:
    #   curl -G "https://services.nvd.nist.gov/rest/json/cves/2.0" \
    #     --data-urlencode "keywordSearch=Zoom" \
    #     --data-urlencode "resultsPerPage=400" | \
    #     jq '.vulnerabilities[].cve | {id,published,...}' | \
    #     jq -s 'sort_by(.published) | reverse[]' > file.txt
    safe_keyword = keyword.replace("'", "'\\''")   # escape single quotes
    shell_cmd = (
        f"curl -G 'https://services.nvd.nist.gov/rest/json/cves/2.0' "
        f"--data-urlencode 'keywordSearch={safe_keyword}' "
        f"--data-urlencode 'resultsPerPage=2000' | "
        f"jq '.vulnerabilities[].cve | {{"
        f"id, published, "
        f"auth_required: (.metrics.cvssMetricV2[0].cvssData.authentication // \"UNKNOWN\"), "
        f"cvss: (.metrics.cvssMetricV31[0].cvssData.baseScore // .metrics.cvssMetricV30[0].cvssData.baseScore // .metrics.cvssMetricV2[0].cvssData.baseScore // null), "
        f"cvss_ver: (if .metrics.cvssMetricV31 then \"3.1\" elif .metrics.cvssMetricV30 then \"3.0\" elif .metrics.cvssMetricV2 then \"2.0\" else null end), "
        f"severity: (.metrics.cvssMetricV31[0].cvssData.baseSeverity // .metrics.cvssMetricV30[0].cvssData.baseSeverity // .metrics.cvssMetricV2[0].baseSeverity // \"UNKNOWN\"), "
        f"vector: (.metrics.cvssMetricV31[0].cvssData.vectorString // .metrics.cvssMetricV30[0].cvssData.vectorString // \"\"), "
        f"cwe: (.weaknesses[0].description[0].value // \"\"), "
        f"description: .descriptions[0].value"
        f"}}' | "
        f"jq -s 'sort_by(.published) | reverse[]' "
        f"> {out_file}"
    )

    print(f"  Fetching...")

    try:
        proc = subprocess.run(
            shell_cmd,
            shell=True,
            executable="/bin/bash",
            capture_output=True,
            text=True,
            timeout=120,
        )

        print(f"  curl exit: {proc.returncode}")
        if proc.stderr:
            # curl writes progress to stderr
            for line in proc.stderr.strip().splitlines()[-3:]:
                if line.strip():
                    print(f"  {line.strip()}")

        if not os.path.exists(out_file):
            print(Fore.YELLOW + "  Output file not created." + Style.RESET_ALL)
            return result

        file_size = os.path.getsize(out_file)
        print(f"  File size: {file_size} bytes")

        if file_size == 0:
            print(Fore.YELLOW + "  Output file empty." + Style.RESET_ALL)
            if proc.stderr:
                print(Fore.YELLOW + f"  stderr: {proc.stderr[:300]}" + Style.RESET_ALL)
            return result

        with open(out_file) as f:
            raw = f.read().strip()

        # Parse newline-delimited JSON objects (output of jq -s 'reverse[]')
        decoder   = json.JSONDecoder()
        entries   = []
        pos       = 0
        while pos < len(raw):
            chunk = raw[pos:].lstrip()
            if not chunk:
                break
            pos += len(raw[pos:]) - len(chunk)
            try:
                obj, offset = decoder.raw_decode(chunk)
                entries.append(obj)
                pos += offset
            except json.JSONDecodeError:
                pos += 1

        print(f"  Parsed {len(entries)} entries — filtering to last 3 years...")

    except subprocess.TimeoutExpired:
        print(Fore.YELLOW + "  Timed out after 120s." + Style.RESET_ALL)
        return result
    except Exception as e:
        print(Fore.YELLOW + f"  Error: {e}" + Style.RESET_ALL)
        return result
    finally:
        try:
            os.unlink(out_file)
        except OSError:
            pass

    # ── Filter to 3 years + build result ─────────────────────────────────────
    def _sev(score) -> str:
        try:
            s = float(score)
            if s >= 9.0: return "CRITICAL"
            if s >= 7.0: return "HIGH"
            if s >= 4.0: return "MEDIUM"
            return "LOW"
        except (TypeError, ValueError):
            return "UNKNOWN"

    for entry in entries:
        published = (entry.get("published") or "")[:10]
        try:
            if datetime.datetime.strptime(published, "%Y-%m-%d") < cutoff_dt:
                continue
        except ValueError:
            pass

        score    = entry.get("cvss")
        severity = (entry.get("severity") or "UNKNOWN").upper()
        if severity in ("UNKNOWN", "") and score:
            severity = _sev(score)
        cwe  = entry.get("cwe", "")
        desc = entry.get("description", "No description.")

        result["cves"].append({
            "id":        entry.get("id", ""),
            "score":     float(score) if score is not None else None,
            "cvss_ver":  entry.get("cvss_ver"),
            "vector":    entry.get("vector", ""),
            "severity":  severity,
            "published": published,
            "modified":  "",
            "cwe":       [cwe] if cwe and "NVD-CWE" not in cwe else [],
            "desc":      desc,
            "summary":   desc[:220],
            "refs":      [],
        })

    result["cves"].sort(key=lambda c: c["score"] or 0, reverse=True)
    result["total"] = len(result["cves"])

    if not result["cves"]:
        print(Fore.GREEN + f"  No CVEs for '{keyword}' since {cutoff_year}." + Style.RESET_ALL)
        return result

    critical = [c for c in result["cves"] if c["severity"] in ("CRITICAL","HIGH")]
    color    = Fore.RED if critical else Fore.YELLOW
    print(f"\n  {color}Found {result['total']} CVE(s) since {cutoff_year}{Style.RESET_ALL}")

    for c in result["cves"][:8]:
        score_str = f"CVSS{c['cvss_ver']} {c['score']}" if c["score"] else "No CVSS"
        sev_color = (Fore.RED    if c["severity"] in ("CRITICAL","HIGH") else
                     Fore.YELLOW if c["severity"] == "MEDIUM" else Fore.WHITE)
        print(f"\n  {sev_color}{c['id']}{Style.RESET_ALL}  [{score_str}]  {c['severity']}  {c['published']}")
        if c["cwe"]:
            print(f"  CWE: {', '.join(c['cwe'])}")
        print(f"  {c['summary'][:110]}{'...' if len(c['summary']) > 110 else ''}")

    return result
    hdr("STEP 12 · CVE SEARCH  (NVD API v2 — last 3 years)")
    result = {"cves": [], "total": 0, "queried": False,
              "app_name": app_name, "version": version}
    if not app_name:
        print("  No --app-name provided — skipping CVE lookup.")
        return result

    result["queried"] = True

    import subprocess

    current_year = datetime.datetime.now().year
    cutoff_year  = current_year - 3
    cutoff_dt    = datetime.datetime(cutoff_year, 1, 1)
    name         = app_name.strip()
    keyword      = f"{name} {version}".strip() if version else name

    nvd_key = os.getenv("NVD_API_KEY", "").strip().strip('"').strip("'").rstrip("$")
    if nvd_key and not re.match(
        r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$',
        nvd_key
    ):
        print(Fore.YELLOW + "  ⚠ NVD_API_KEY malformed — using unauthenticated (5 req/30s)" + Style.RESET_ALL)
        nvd_key = ""

    print(f"  App    : {Fore.WHITE}{keyword}{Style.RESET_ALL}")
    print(f"  Since  : {cutoff_year}-01-01")
    print(f"  Key    : {'✓ NVD_API_KEY set (50 req/30s)' if nvd_key else '⚠ No key — 5 req/30s'}")

    out_file = f"/tmp/nvd_{os.getpid()}.json"

    # jq filter — extracts id, published, description, cvss score+severity, cwe
    # then sorts by published desc, outputs newline-delimited JSON objects
    jq_filter = (
        '.vulnerabilities[].cve | {'
        'id,'
        'published,'
        'description: .descriptions[0].value,'
        'cvss: (.metrics.cvssMetricV31[0].cvssData.baseScore // '
               '.metrics.cvssMetricV30[0].cvssData.baseScore // '
               '.metrics.cvssMetricV2[0].cvssData.baseScore // null),'
        'cvss_ver: (if .metrics.cvssMetricV31 then "3.1" '
                  'elif .metrics.cvssMetricV30 then "3.0" '
                  'elif .metrics.cvssMetricV2  then "2.0" '
                  'else null end),'
        'severity: (.metrics.cvssMetricV31[0].cvssData.baseSeverity // '
                   '.metrics.cvssMetricV30[0].cvssData.baseSeverity // '
                   '.metrics.cvssMetricV2[0].baseSeverity // "UNKNOWN"),'
        'vector: (.metrics.cvssMetricV31[0].cvssData.vectorString // '
                 '.metrics.cvssMetricV30[0].cvssData.vectorString // ""),'
        'cwe: (.weaknesses[0].description[0].value // ""),'
        'refs: [.references[].url] | .[:3]'
        '}'
    )

    try:
        print(f"  Running curl | jq → {out_file}")

        # Exact proven pipeline: curl -G --data-urlencode | jq | jq -s > file
        curl_cmd = [
            "curl", "-G",
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "--data-urlencode", f"keywordSearch={keyword}",
            "--data-urlencode", "resultsPerPage=2000",
        ]
        if nvd_key:
            curl_cmd += ["--header", f"apiKey: {nvd_key}"]

        jq_cmd1  = ["jq", jq_filter]
        jq_cmd2  = ["jq", "-s", "sort_by(.published) | reverse[]"]

        # Pipeline: curl | jq filter | jq sort > file
        p_curl = subprocess.Popen(curl_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p_jq1  = subprocess.Popen(jq_cmd1,  stdin=p_curl.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        p_curl.stdout.close()

        with open(out_file, "w") as fout:
            p_jq2 = subprocess.Popen(jq_cmd2, stdin=p_jq1.stdout, stdout=fout, stderr=subprocess.PIPE)
            p_jq1.stdout.close()
            p_jq2.wait()

        p_curl.wait()
        p_jq1.wait()

        curl_err = p_curl.stderr.read().decode()
        # curl writes progress to stderr — extract bytes transferred
        bytes_line = [l for l in curl_err.splitlines() if "%" in l or "Total" in l]
        if bytes_line:
            print(f"  curl: {bytes_line[-1].strip()}")

        if p_curl.returncode not in (0, None):
            print(Fore.YELLOW + f"  curl error (exit {p_curl.returncode}): {curl_err[:100]}" + Style.RESET_ALL)
            return result

        # Read and parse the output file
        with open(out_file) as f:
            raw = f.read().strip()

        if not raw:
            print(Fore.YELLOW + "  Output file empty — check jq is installed (pacman -S jq)" + Style.RESET_ALL)
            return result

        file_size = len(raw)
        print(f"  File size: {file_size} bytes")

        # Parse newline-delimited JSON objects
        all_entries = []
        decoder = json.JSONDecoder()
        pos = 0
        raw = raw.strip()
        while pos < len(raw):
            raw_slice = raw[pos:].lstrip()
            if not raw_slice:
                break
            pos += len(raw[pos:]) - len(raw_slice)
            try:
                obj, offset = decoder.raw_decode(raw_slice)
                all_entries.append(obj)
                pos += offset
            except json.JSONDecodeError:
                pos += 1

        print(f"  Parsed {len(all_entries)} CVE entries — filtering to last 3 years...")

    except FileNotFoundError as e:
        missing = str(e).split("'")[1] if "'" in str(e) else str(e)
        print(Fore.YELLOW + f"  Required tool not found: {missing}" + Style.RESET_ALL)
        print(Fore.YELLOW + "  Install with: sudo pacman -S curl jq" + Style.RESET_ALL)
        return result
    except Exception as e:
        print(Fore.YELLOW + f"  Error: {e}" + Style.RESET_ALL)
        return result
    finally:
        try:
            os.unlink(out_file)
            print(f"  Temp file purged.")
        except OSError:
            pass

    # ── Filter to last 3 years + build result entries ─────────────────────────
    def _severity_from_score(score) -> str:
        try:
            s = float(score)
            if s >= 9.0: return "CRITICAL"
            if s >= 7.0: return "HIGH"
            if s >= 4.0: return "MEDIUM"
            if s >  0.0: return "LOW"
        except (TypeError, ValueError):
            pass
        return "UNKNOWN"

    for entry in all_entries:
        published = (entry.get("published") or "")[:10]
        try:
            if datetime.datetime.strptime(published, "%Y-%m-%d") < cutoff_dt:
                continue
        except ValueError:
            pass

        score    = entry.get("cvss")
        severity = (entry.get("severity") or "UNKNOWN").upper()
        if severity == "UNKNOWN" and score:
            severity = _severity_from_score(score)
        cwe = entry.get("cwe", "")
        cwe_list = [cwe] if cwe and "NVD-CWE" not in cwe else []
        desc = entry.get("description", "No description.")

        result["cves"].append({
            "id":        entry.get("id", ""),
            "score":     float(score) if score is not None else None,
            "cvss_ver":  entry.get("cvss_ver"),
            "vector":    entry.get("vector", ""),
            "severity":  severity,
            "published": published,
            "modified":  "",
            "cwe":       cwe_list,
            "desc":      desc,
            "summary":   desc[:220],
            "refs":      entry.get("refs", []),
        })

    # Already sorted by jq (published desc), re-sort by score for display
    result["cves"].sort(key=lambda c: c["score"] or 0, reverse=True)
    result["total"] = len(result["cves"])

    if not result["cves"]:
        print(Fore.GREEN + f"  No CVEs for '{keyword}' since {cutoff_year}." + Style.RESET_ALL)
        return result

    critical = [c for c in result["cves"] if c["severity"] in ("CRITICAL", "HIGH")]
    color    = Fore.RED if critical else Fore.YELLOW
    print(f"\n  {color}Found {result['total']} CVE(s) since {cutoff_year}{Style.RESET_ALL}")

    for c in result["cves"][:8]:
        score_str = f"CVSS{c['cvss_ver']} {c['score']}" if c["score"] else "No CVSS"
        sev_color = (Fore.RED    if c["severity"] in ("CRITICAL", "HIGH") else
                     Fore.YELLOW if c["severity"] == "MEDIUM" else Fore.WHITE)
        print(f"\n  {sev_color}{c['id']}{Style.RESET_ALL}  [{score_str}]  {c['severity']}  {c['published']}")
        if c["cwe"]:
            print(f"  CWE: {', '.join(c['cwe'])}")
        print(f"  {c['summary'][:110]}{'...' if len(c['summary']) > 110 else ''}")

    return result
    hdr("STEP 12 · CVE SEARCH  (NVD API v2 — last 3 years)")
    result = {"cves": [], "total": 0, "queried": False,
              "app_name": app_name, "version": version}
    if not app_name:
        print("  No --app-name provided — skipping CVE lookup.")
        return result

    result["queried"] = True

    import subprocess

    current_year = datetime.datetime.now().year
    cutoff_year  = current_year - 3
    cutoff_dt    = datetime.datetime(cutoff_year, 1, 1)
    name         = app_name.strip()
    keyword      = f"{name} {version}".strip() if version else name

    nvd_key = os.getenv("NVD_API_KEY", "").strip().strip('"').strip("'").rstrip("$")
    if nvd_key and not re.match(
        r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$',
        nvd_key
    ):
        print(Fore.YELLOW + "  ⚠ NVD_API_KEY malformed — using unauthenticated (5 req/30s)" + Style.RESET_ALL)
        nvd_key = ""

    print(f"  App    : {Fore.WHITE}{keyword}{Style.RESET_ALL}")
    print(f"  Since  : {cutoff_year}-01-01")
    print(f"  Key    : {'✓ NVD_API_KEY set (50 req/30s)' if nvd_key else '⚠ No key — 5 req/30s'}")

    # Use /tmp/nvd_<pid>.json so parallel runs don't collide
    out_file = f"/tmp/nvd_{os.getpid()}.json"

    # Build curl command — pipe stdout to file (proven pattern)
    cmd = [
        "curl", "-G",
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "--data-urlencode", f"keywordSearch={keyword}",
        "--data-urlencode", "resultsPerPage=2000",
        "--silent",
        "--max-time", "60",
    ]
    if nvd_key:
        cmd += ["--header", f"apiKey: {nvd_key}"]

    try:
        print(f"  Fetching from NVD...", end="", flush=True)

        # Write stdout directly to file — same as > out_file in shell
        with open(out_file, "w") as fout:
            proc = subprocess.run(cmd, stdout=fout, stderr=subprocess.PIPE,
                                  timeout=65)

        if proc.returncode != 0:
            print(f"\n  curl failed (exit {proc.returncode}): {proc.stderr.decode()[:100]}")
            return result

        # Read the file
        with open(out_file) as f:
            raw = f.read().strip()

        print(f" {len(raw)} bytes received")

        if not raw:
            print(Fore.YELLOW + "  NVD returned empty response." + Style.RESET_ALL)
            return result

        data = json.loads(raw)

        if "message" in data:
            print(Fore.RED + f"  NVD API error: {data['message']}" + Style.RESET_ALL)
            return result

        all_items = data.get("vulnerabilities", [])
        total_nvd = data.get("totalResults", 0)
        print(f"  NVD total matches: {total_nvd} — filtering to last 3 years...")

    except FileNotFoundError:
        print(Fore.YELLOW + "\n  curl not found — install curl." + Style.RESET_ALL)
        return result
    except json.JSONDecodeError as e:
        print(Fore.YELLOW + f"\n  JSON parse error: {e}" + Style.RESET_ALL)
        print(Fore.YELLOW + f"  Raw preview: {raw[:200]}" + Style.RESET_ALL)
        return result
    except Exception as e:
        print(Fore.YELLOW + f"\n  Error: {e}" + Style.RESET_ALL)
        return result
    finally:
        # Always purge the temp file
        try:
            os.unlink(out_file)
        except OSError:
            pass

    # ── Parse + 3-year client-side filter ────────────────────────────────────
    def _severity(score) -> str:
        try:
            s = float(score)
            if s >= 9.0: return "CRITICAL"
            if s >= 7.0: return "HIGH"
            if s >= 4.0: return "MEDIUM"
            if s >  0.0: return "LOW"
        except (TypeError, ValueError):
            pass
        return "UNKNOWN"

    for item in all_items:
        cve       = item.get("cve", {})
        published = cve.get("published", "")[:10]

        try:
            if datetime.datetime.strptime(published, "%Y-%m-%d") < cutoff_dt:
                continue
        except ValueError:
            pass

        cve_id   = cve.get("id", "")
        descs    = cve.get("descriptions", [])
        desc     = next((d["value"] for d in descs if d.get("lang") == "en"),
                        "No description.")
        modified = cve.get("lastModified", "")[:10]
        refs     = [r["url"] for r in cve.get("references", [])[:3]]
        cwe_list = [
            w.get("description", [{}])[0].get("value", "")
            for w in cve.get("weaknesses", []) if w.get("description")
        ][:3]
        cwe_list = [c for c in cwe_list if c and "NVD-CWE" not in c]

        metrics    = cve.get("metrics", {})
        cvss_score = None
        cvss_vec   = None
        cvss_ver   = None
        severity   = "UNKNOWN"

        for mkey, ver in (
            ("cvssMetricV40", "4.0"),
            ("cvssMetricV31", "3.1"),
            ("cvssMetricV30", "3.0"),
            ("cvssMetricV2",  "2.0"),
        ):
            if mkey in metrics and metrics[mkey]:
                m          = metrics[mkey][0]
                cd         = m.get("cvssData", {})
                cvss_score = cd.get("baseScore")
                cvss_vec   = cd.get("vectorString", "")
                severity   = cd.get("baseSeverity") or m.get("baseSeverity", "UNKNOWN")
                cvss_ver   = ver
                break

        if severity == "UNKNOWN" and cvss_score:
            severity = _severity(cvss_score)

        result["cves"].append({
            "id":        cve_id,
            "score":     cvss_score,
            "cvss_ver":  cvss_ver,
            "vector":    cvss_vec,
            "severity":  severity.upper() if severity else "UNKNOWN",
            "published": published,
            "modified":  modified,
            "cwe":       cwe_list,
            "desc":      desc,
            "summary":   desc[:220],
            "refs":      refs,
        })

    result["cves"].sort(key=lambda c: c["score"] or 0, reverse=True)
    result["total"] = len(result["cves"])

    if not result["cves"]:
        print(Fore.GREEN + f"  No CVEs for '{keyword}' since {cutoff_year}." + Style.RESET_ALL)
        return result

    critical = [c for c in result["cves"] if c["severity"] in ("CRITICAL", "HIGH")]
    color    = Fore.RED if critical else Fore.YELLOW
    print(f"\n  {color}Found {result['total']} CVE(s) since {cutoff_year}{Style.RESET_ALL}")

    for c in result["cves"][:8]:
        score_str = f"CVSS{c['cvss_ver']} {c['score']}" if c["score"] else "No CVSS"
        sev_color = (Fore.RED    if c["severity"] in ("CRITICAL", "HIGH") else
                     Fore.YELLOW if c["severity"] == "MEDIUM" else Fore.WHITE)
        print(f"\n  {sev_color}{c['id']}{Style.RESET_ALL}  [{score_str}]  {c['severity']}  {c['published']}")
        if c["cwe"]:
            print(f"  CWE: {', '.join(c['cwe'])}")
        print(f"  {c['summary'][:110]}{'...' if len(c['summary']) > 110 else ''}")

    return result



def compute_risk_score(circl, vt, mb, urlhaus, threatfox, otx, pe, strings, meta, appcat, mitre=None) -> int:
    if circl.get("known_good"):
        return 0  # CIRCL hit = instantly known good, skip scoring

    s  = vt.get("detections", 0) * RISK_WEIGHTS["vt_detections"]
    s += RISK_WEIGHTS["mb_known_malware"] if mb.get("found") else 0
    s += otx.get("pulses", 0) * RISK_WEIGHTS["otx_pulses"]
    s += sum(1 for sec in pe.get("sections", []) if sec.get("high")) * RISK_WEIGHTS["high_entropy"]
    s += len(pe.get("suspicious_imports", [])) * RISK_WEIGHTS["suspicious_imports"]
    s += len(strings.get("hits", [])) * RISK_WEIGHTS["suspicious_strings"]
    s += len(urlhaus.get("hits", [])) * RISK_WEIGHTS["urlhaus_hit"]
    s += RISK_WEIGHTS["threatfox_hit"] if threatfox.get("hash_hit") else 0
    s += len(threatfox.get("ip_hits", [])) * RISK_WEIGHTS["greynoise_malicious"]
    s += RISK_WEIGHTS["magic_mismatch"] if meta.get("magic_mismatch") else 0
    if appcat.get("primary_category") in ("remote_access", "packet_capture", "credential_tool", "vpn_tunnel"):
        s += RISK_WEIGHTS["rat_category"]

    # Vuln risk — critical/high CVEs bump score
    if mitre:
        critical_cves = [c for c in mitre.get("cves", []) if c["severity"] in ("CRITICAL", "HIGH")]
        s += min(len(critical_cves) * 5, 20)  # max +20 from MITRE CVEs

    return min(s, 100)


# ─── PDF Report ───────────────────────────────────────────────────────────────

def build_pdf(filepath: str, hashes: dict, meta: dict, appcat: dict,
              pe: dict, strings: dict, circl: dict, vt: dict, mb: dict,
              urlhaus: dict, threatfox: dict, otx: dict, risk: int,
              mitre: dict = None) -> str:
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, PageBreak,
        )
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
    except ImportError:
        print(Fore.YELLOW + "\n  reportlab not installed — skipping PDF. Run: pip install reportlab" + Style.RESET_ALL)
        return ""

    # ── Palette ──────────────────────────────────────────────────────────────
    C_BG     = colors.HexColor("#0d1117")
    C_PANEL  = colors.HexColor("#161b22")
    C_BORDER = colors.HexColor("#30363d")
    C_ACCENT = colors.HexColor("#58a6ff")
    C_GREEN  = colors.HexColor("#3fb950")
    C_YELLOW = colors.HexColor("#d29922")
    C_RED    = colors.HexColor("#f85149")
    C_WHITE  = colors.HexColor("#e6edf3")
    C_MUTED  = colors.HexColor("#8b949e")

    risk_color = C_GREEN if risk == 0 else (C_YELLOW if risk < 30 else (colors.HexColor("#f0883e") if risk < 70 else C_RED))
    risk_word  = "CLEAN" if risk == 0 else ("LOW" if risk < 30 else ("MEDIUM" if risk < 70 else "HIGH"))

    out_path = filepath if filepath.endswith(".pdf") else filepath + ".pdf"
    doc = SimpleDocTemplate(
        out_path, pagesize=letter,
        leftMargin=0.65*inch, rightMargin=0.65*inch,
        topMargin=0.7*inch, bottomMargin=0.65*inch,
    )

    base = getSampleStyleSheet()
    def sty(name, **kw):
        return ParagraphStyle(name, parent=base["Normal"], **kw)

    S = {
        "title":   sty("title",   fontSize=22, textColor=C_WHITE, fontName="Helvetica-Bold", spaceAfter=4, alignment=TA_CENTER),
        "sub":     sty("sub",     fontSize=10, textColor=C_MUTED,  fontName="Helvetica",      spaceAfter=2, alignment=TA_CENTER),
        "h2":      sty("h2",      fontSize=13, textColor=C_ACCENT, fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=4),
        "body":    sty("body",    fontSize=9,  textColor=C_WHITE,  fontName="Helvetica",       leading=14),
        "mono":    sty("mono",    fontSize=7.5,textColor=C_WHITE,  fontName="Courier",         leading=12),
        "label":   sty("label",   fontSize=8,  textColor=C_MUTED,  fontName="Helvetica"),
        "warn":    sty("warn",    fontSize=9,  textColor=C_RED,    fontName="Helvetica-Bold"),
        "ok":      sty("ok",      fontSize=9,  textColor=C_GREEN,  fontName="Helvetica-Bold"),
        "risk_big":sty("risk_big",fontSize=28, textColor=risk_color,fontName="Helvetica-Bold", alignment=TA_CENTER),
    }

    def hr(): return HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=8, spaceBefore=4)
    def sp(h=6): return Spacer(1, h)

    def kv_table(rows, col_widths=(2.2*inch, 5.0*inch)):
        data = [[Paragraph(k, S["label"]), Paragraph(str(v), S["mono"])] for k, v in rows]
        t = Table(data, colWidths=col_widths)
        t.setStyle(TableStyle([
            ("BACKGROUND",  (0,0), (-1,-1), C_PANEL),
            ("ROWBACKGROUNDS",(0,0),(-1,-1),[C_PANEL, colors.HexColor("#1c2128")]),
            ("TEXTCOLOR",   (0,0), (-1,-1), C_WHITE),
            ("FONTSIZE",    (0,0), (-1,-1), 8),
            ("TOPPADDING",  (0,0), (-1,-1), 5),
            ("BOTTOMPADDING",(0,0),(-1,-1), 5),
            ("LEFTPADDING", (0,0), (-1,-1), 8),
            ("BOX",         (0,0), (-1,-1), 0.5, C_BORDER),
            ("LINEBELOW",   (0,0), (-1,-1), 0.3, C_BORDER),
        ]))
        return t

    def badge_table(label, value, color):
        data = [[Paragraph(label, S["label"]), Paragraph(str(value), ParagraphStyle("bv", parent=base["Normal"], textColor=color, fontName="Helvetica-Bold", fontSize=9))]]
        t = Table(data, colWidths=[2.2*inch, 5.0*inch])
        t.setStyle(TableStyle([
            ("BACKGROUND",   (0,0),(-1,-1), C_PANEL),
            ("TOPPADDING",   (0,0),(-1,-1), 5),
            ("BOTTOMPADDING",(0,0),(-1,-1), 5),
            ("LEFTPADDING",  (0,0),(-1,-1), 8),
            ("BOX",          (0,0),(-1,-1), 0.5, C_BORDER),
        ]))
        return t

    story = []

    # ── Cover ─────────────────────────────────────────────────────────────────
    story += [
        sp(20),
        Paragraph("FILE TRIAGE REPORT", S["title"]),
        Paragraph("First-Level Malware &amp; Application Intelligence", S["sub"]),
        sp(4),
        Paragraph(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", S["sub"]),
        sp(18),
        Paragraph(risk_word, S["risk_big"]),
        Paragraph(f"Risk Score: {risk} / 100", sty("rs", fontSize=11, textColor=risk_color, fontName="Helvetica", alignment=TA_CENTER, spaceAfter=4)),
        sp(16),
    ]

    # Recommendation box
    if risk == 0:
        rec_text = "KNOWN GOOD — File matches CIRCL trusted database. Standard install approved."
        rec_color = C_GREEN
    elif risk >= 70:
        rec_text  = "DO NOT INSTALL — High-risk indicators detected. Escalate to security team immediately."
        rec_color = C_RED
    elif risk >= 30:
        rec_text  = "CAUTION — Moderate risk. Investigate further before permitting installation."
        rec_color = C_YELLOW
    else:
        rec_text  = "LOW RISK — No major threat intel hits. Standard pre-install review advised."
        rec_color = C_GREEN

    rec_style = ParagraphStyle("rec", parent=base["Normal"], textColor=rec_color,
                                fontName="Helvetica-Bold", fontSize=10, alignment=TA_CENTER,
                                borderPad=10, borderColor=rec_color, borderWidth=1,
                                backColor=C_PANEL, spaceAfter=12)
    story.append(Paragraph(rec_text, rec_style))
    story.append(PageBreak())

    # ── Section 1: File Identity ───────────────────────────────────────────────
    story.append(Paragraph("1. FILE IDENTITY", S["h2"]))
    story.append(hr())
    story.append(kv_table([
        ("Filename",      meta["filename"]),
        ("Size",          meta["size_human"]),
        ("Extension",     meta["extension"]),
        ("Detected Type", meta["detected_type"]),
        ("Magic Mismatch",("⚠ YES — Possible extension spoofing" if meta.get("magic_mismatch") else "No")),
        ("Modified",      meta["modified"]),
        ("MD5",           hashes["md5"]),
        ("SHA1",          hashes["sha1"]),
        ("SHA256",        hashes["sha256"]),
    ]))
    story.append(sp())

    # ── Section 2: Application Classification ─────────────────────────────────
    story.append(Paragraph("2. APPLICATION CLASSIFICATION", S["h2"]))
    story.append(hr())
    if appcat["matches"]:
        for m in appcat["matches"]:
            story.append(kv_table([
                ("Category",    m["display"]),
                ("Policy Note", m["note"]),
            ]))
            story.append(sp(4))
    else:
        story.append(Paragraph("No specific application category matched — general/unknown binary.", S["body"]))
    story.append(sp())

    # ── Section 3: CIRCL Known-Good ───────────────────────────────────────────
    story.append(Paragraph("3. CIRCL HASHLOOKUP (Known-Good Check)", S["h2"]))
    story.append(hr())
    if circl.get("known_good"):
        story.append(badge_table("Status", "✓ KNOWN GOOD — in CIRCL trusted database", C_GREEN))
        story.append(sp(4))
        story.append(kv_table([
            ("Source",    circl["info"].get("db_source", "N/A")),
            ("Trust",     circl["info"].get("trust", "N/A")),
        ]))
    else:
        story.append(badge_table("Status", "Not in CIRCL known-good DB — file is unknown or new", C_YELLOW))
    story.append(sp())

    # ── Section 4: Threat Intel APIs ──────────────────────────────────────────
    story.append(Paragraph("4. THREAT INTELLIGENCE", S["h2"]))
    story.append(hr())

    # VT
    vt_val   = f"{vt['detections']}/{vt['total']} engines" if vt.get("checked") else "N/A (no API key)"
    vt_color = C_RED if vt.get("detections",0) > 0 else C_GREEN
    story.append(badge_table("VirusTotal", vt_val, vt_color))
    if vt.get("flagging_engines"):
        story.append(sp(4))
        for fe in vt["flagging_engines"][:6]:
            story.append(Paragraph(f"  ⚠  {fe}", S["warn"]))
    story.append(sp(6))

    # MB
    mb_val   = f"⚠ KNOWN MALWARE — {mb['malware_family']}" if mb.get("found") else "Not listed"
    mb_color = C_RED if mb.get("found") else C_GREEN
    story.append(badge_table("MalwareBazaar", mb_val, mb_color))
    story.append(sp(6))

    # URLhaus
    uh_val   = f"⚠ {len(urlhaus['hits'])} malicious URL(s) found" if urlhaus.get("hits") else "No malicious URLs detected"
    uh_color = C_RED if urlhaus.get("hits") else C_GREEN
    story.append(badge_table("URLhaus", uh_val, uh_color))
    if urlhaus.get("hits"):
        story.append(sp(4))
        for h in urlhaus["hits"]:
            story.append(Paragraph(f"  ⚠  {h['url'][:80]} ({h['threat']})", S["warn"]))
    story.append(sp(6))

    # ThreatFox
    tf_val   = f"⚠ Hash in ThreatFox — {threatfox.get('ioc_details',{}).get('malware','?')}" if threatfox.get("hash_hit") else "Not in ThreatFox"
    tf_color = C_RED if threatfox.get("hash_hit") else C_GREEN
    story.append(badge_table("ThreatFox", tf_val, tf_color))
    story.append(sp(6))

    # OTX
    otx_val   = f"⚠ {otx['pulses']} threat pulse(s)" if otx.get("pulses",0) > 0 else ("Not checked (no key)" if not otx.get("checked") else "No threat pulses")
    otx_color = C_RED if otx.get("pulses",0) > 0 else C_GREEN
    story.append(badge_table("AlienVault OTX", otx_val, otx_color))
    story.append(sp())

    # ── Section 5: PE Analysis ────────────────────────────────────────────────
    story.append(Paragraph("5. PE HEADER ANALYSIS", S["h2"]))
    story.append(hr())
    if pe.get("is_pe"):
        story.append(kv_table([
            ("Architecture", pe.get("machine","N/A")),
            ("Compiled",     pe.get("compiled","N/A")),
            ("Subsystem",    pe.get("subsystem","N/A")),
            ("Imphash",      pe.get("imphash","N/A")),
        ]))
        story.append(sp(6))
        if pe.get("suspicious_imports"):
            story.append(Paragraph("Suspicious Imports:", S["warn"]))
            for imp in pe["suspicious_imports"]:
                story.append(Paragraph(f"  ⚠  {imp}", S["warn"]))
        else:
            story.append(Paragraph("No suspicious imports found.", S["ok"]))
        high_secs = [s for s in pe.get("sections",[]) if s.get("high")]
        if high_secs:
            story.append(sp(4))
            story.append(Paragraph("High-Entropy Sections (possible packing):", S["warn"]))
            for s in high_secs:
                story.append(Paragraph(f"  ⚠  {s['name']}  entropy={s['entropy']}", S["warn"]))
    else:
        story.append(Paragraph("Not a PE/EXE file — PE analysis not applicable.", S["body"]))
    story.append(sp())

    # ── Section 6: Strings & IOCs ─────────────────────────────────────────────
    story.append(Paragraph("6. SUSPICIOUS STRINGS &amp; IOCs", S["h2"]))
    story.append(hr())
    if strings.get("hits"):
        for hit in strings["hits"]:
            story.append(Paragraph(f"⚠  {hit['label']}", S["warn"]))
            for s in hit["samples"][:3]:
                story.append(Paragraph(f"   → {s[:90]}", S["mono"]))
            story.append(sp(3))
    else:
        story.append(Paragraph("No suspicious string patterns matched.", S["ok"]))
    if strings.get("ips"):
        story.append(sp(4))
        story.append(Paragraph(f"Extracted IPs: {', '.join(strings['ips'][:8])}", S["body"]))
    if strings.get("urls"):
        story.append(Paragraph(f"Extracted URLs: {len(strings['urls'])} found", S["body"]))

    # ── Section 7: MITRE CVE Vulnerabilities ──────────────────────────────────
    story.append(Paragraph("7. MITRE / NVD CVE VULNERABILITIES  (last 4 years)", S["h2"]))
    story.append(hr())
    if mitre and mitre.get("queried"):
        app_label  = mitre.get("app_name", "")
        ver_label  = f"  v{mitre['version']}" if mitre.get("version") else ""
        now_label  = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).strftime("%Y-%m-%d")
        cutoff_lbl = (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - datetime.timedelta(days=4*365)).strftime("%Y-%m-%d")
        story.append(Paragraph(
            f"Application: {app_label}{ver_label}  |  Window: {cutoff_lbl} to {now_label}  |  Total matching: {mitre.get('total', 0)}",
            S["body"],
        ))
        story.append(sp(8))
        if mitre.get("cves"):
            for c in mitre["cves"][:10]:
                score_str = f"CVSS v{c['cvss_ver']}  {c['score']}" if c.get("score") else "No CVSS score"
                sev_color = C_RED if c["severity"] in ("CRITICAL", "HIGH") else (C_YELLOW if c["severity"] == "MEDIUM" else C_GREEN)
                rows = [
                    ("CVE ID",      c["id"]),
                    ("Severity",    c["severity"]),
                    ("CVSS Score",  score_str),
                ]
                if c.get("vector"):
                    rows.append(("CVSS Vector", c["vector"]))
                if c.get("cwe"):
                    rows.append(("CWE",         ", ".join(c["cwe"])))
                rows += [
                    ("Published",   c["published"]),
                    ("Last Modified", c.get("modified", "N/A")),
                    ("Description", c["desc"][:400]),
                ]
                if c.get("refs"):
                    rows.append(("References", "  |  ".join(c["refs"][:2])))
                story.append(kv_table(rows, col_widths=(1.8*inch, 5.4*inch)))
                story.append(sp(6))
        else:
            story.append(Paragraph(
                f"No CVEs found for '{mitre.get('app_name')}' in the last 4 years.",
                S["ok"],
            ))
    else:
        story.append(Paragraph(
            "No application name provided — pass --app-name to enable CVE lookup.",
            sty("na", textColor=C_MUTED, fontSize=9, fontName="Helvetica"),
        ))
    story.append(sp())

    # ── Footer note ───────────────────────────────────────────────────────────
    story.append(sp(20))
    story.append(hr())
    story.append(Paragraph(
        "This report is generated for first-level triage purposes only. "
        "A low or clean score does not guarantee the file is safe — it indicates no known threat "
        "intel matches at the time of scan. For high-risk findings, escalate to a security analyst.",
        sty("footer", fontSize=7.5, textColor=C_MUTED, fontName="Helvetica", alignment=TA_CENTER),
    ))

    # ── Page background via canvas override ───────────────────────────────────
    def dark_bg(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(C_BG)
        canvas.rect(0, 0, letter[0], letter[1], fill=1, stroke=0)
        canvas.restoreState()

    doc.build(story, onFirstPage=dark_bg, onLaterPages=dark_bg)
    return out_path


# ─── Console Summary ─────────────────────────────────────────────────────────

def print_summary(meta, hashes, appcat, pe, circl, vt, mb, urlhaus, threatfox, otx, strings, risk,
                  mitre=None):
    hdr("TRIAGE SUMMARY")
    vt_str  = f"{vt['detections']}/{vt['total']} engines" if vt.get("checked") else "N/A (no key)"
    mb_str  = f"⚠ {mb['malware_family']}" if mb.get("found") else "Not listed"
    uh_str  = f"⚠ {len(urlhaus['hits'])} malicious URL(s)" if urlhaus.get("hits") else "Clean"
    tf_str  = f"⚠ {threatfox['ioc_details'].get('malware','?')}" if threatfox.get("hash_hit") else "Not listed"
    ot_str  = f"⚠ {otx['pulses']} pulse(s)" if otx.get("pulses",0) > 0 else ("Not checked" if not otx.get("checked") else "Clean")
    cg_str  = Fore.GREEN + "✓ KNOWN GOOD" + Style.RESET_ALL if circl.get("known_good") else "Unknown"
    cat_str = appcat["matches"][0]["display"] if appcat["matches"] else "Unknown / Generic"

    # Vuln summary strings
    if mitre and mitre.get("queried"):
        crit_cves = [c for c in mitre.get("cves",[]) if c["severity"] in ("CRITICAL","HIGH")]
        cve_str   = (Fore.RED + f"⚠ {mitre['total']} CVEs ({len(crit_cves)} critical/high)" + Style.RESET_ALL) if mitre["total"] else Fore.GREEN + "None found" + Style.RESET_ALL
    else:
        cve_str = "N/A (no --app-name)"


    rows = [
        ["File",               meta["filename"]],
        ["Size",               meta["size_human"]],
        ["Detected Type",      meta["detected_type"]],
        ["Magic Mismatch",     Fore.RED+"YES"+Style.RESET_ALL if meta.get("magic_mismatch") else "No"],
        ["App Category",       cat_str],
        ["CIRCL Known-Good",   cg_str],
        ["VT Detections",      vt_str],
        ["MalwareBazaar",      mb_str],
        ["URLhaus",            uh_str],
        ["ThreatFox",          tf_str],
        ["OTX Pulses",         ot_str],
        ["MITRE CVEs",         cve_str],
        ["Suspicious Imports", str(len(pe.get("suspicious_imports", [])))],
        ["String Hits",        str(len(strings.get("hits", [])))],
        ["SHA256",             hashes["sha256"]],
        ["RISK SCORE",         risk_label(risk)],
    ]
    print(tabulate(rows, tablefmt="rounded_outline"))
    print()
    if risk == 0 and circl.get("known_good"):
        print(Fore.GREEN  + "  ▶ KNOWN GOOD — matches CIRCL trusted hash database." + Style.RESET_ALL)
    elif risk >= 70:
        print(Fore.RED    + "  ▶ DO NOT INSTALL — escalate to security team." + Style.RESET_ALL)
    elif risk >= 30:
        print(Fore.YELLOW + "  ▶ CAUTION — investigate before permitting installation." + Style.RESET_ALL)
    else:
        print(Fore.GREEN  + "  ▶ LOW RISK — no major threat intel hits detected." + Style.RESET_ALL)
    print()


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="file_triage.py v3.0 — First-Level Malware Triage Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment variables:
  VIRUSTOTAL_API_KEY    https://www.virustotal.com  (free)
  OTX_API_KEY           https://otx.alienvault.com  (free)
  GREYNOISE_API_KEY     https://greynoise.io        (community free)

No key needed for: CIRCL hashlookup, MalwareBazaar, URLhaus, ThreatFox

Examples:
  python file_triage.py suspicious.exe
  python file_triage.py setup.exe --app-name "TeamViewer"
  python file_triage.py setup.exe --app-name "AnyDesk" --version "8.0.8" --pdf
  python file_triage.py setup.exe --app-name "Zoom" --pdf /reports/zoom_triage.pdf
  python file_triage.py setup.exe --json > report.json
  VIRUSTOTAL_API_KEY=abc OTX_API_KEY=xyz python file_triage.py app.exe --app-name "ngrok" --pdf
        """,
    )
    parser.add_argument("filepath",      help="Path to the file to triage")
    parser.add_argument("--app-name",    metavar="NAME",    default="",
                        help='Application name for NVD CVE lookup (e.g. "TeamViewer", "AnyDesk")')
    parser.add_argument("--version",     metavar="VERSION", default="",
                        help='Application version for targeted CVE search (e.g. "15.0.8397")')
    parser.add_argument("--pdf",         nargs="?", const="__auto__", metavar="OUTPUT.PDF",
                        help="Generate PDF report (optional: specify output path)")
    parser.add_argument("--json",        action="store_true", help="Also print JSON summary")
    parser.add_argument("--no-banner",   action="store_true", help="Suppress ASCII banner")
    args = parser.parse_args()

    if not os.path.isfile(args.filepath):
        print(Fore.RED + f"\n  Error: File not found — {args.filepath}\n" + Style.RESET_ALL)
        sys.exit(1)

    if not args.no_banner:
        banner()

    started  = datetime.datetime.now()
    app_name = args.app_name.strip()
    version  = args.version.strip()

    print(f"  Triaging : {Fore.WHITE}{args.filepath}{Style.RESET_ALL}")
    if app_name:
        print(f"  App name : {Fore.WHITE}{app_name}{f'  v{version}' if version else ''}{Style.RESET_ALL}")
    print(f"  Started  : {started.strftime('%Y-%m-%d %H:%M:%S')}")

    # Run all steps
    hashes   = compute_hashes(args.filepath)
    meta     = file_metadata(args.filepath)
    appcat   = classify_application(args.filepath)
    pe       = analyze_pe(args.filepath)
    strings  = extract_strings_and_iocs(args.filepath)
    circl    = query_circl(hashes["sha256"])
    vt       = query_virustotal(hashes["sha256"])
    mb       = query_malwarebazaar(hashes["sha256"])
    urlhaus  = query_urlhaus(strings.get("urls", []))
    threatfx = query_threatfox(hashes["sha256"], strings.get("ips", []))
    otx      = query_otx(hashes["sha256"])
    cve_det  = query_nvd_cve(app_name, version)
    risk     = compute_risk_score(circl, vt, mb, urlhaus, threatfx, otx, pe, strings, meta, appcat,
                                  mitre=cve_det)

    print_summary(meta, hashes, appcat, pe, circl, vt, mb, urlhaus, threatfx, otx, strings, risk,
                  mitre=cve_det)

    # PDF
    if args.pdf is not None:
        if args.pdf == "__auto__":
            stem    = Path(args.filepath).stem
            ts      = started.strftime("%Y%m%d_%H%M%S")
            pdf_out = str(Path(args.filepath).parent / f"triage_{stem}_{ts}.pdf")
        else:
            pdf_out = args.pdf

        hdr("GENERATING PDF REPORT")
        path = build_pdf(pdf_out, hashes, meta, appcat, pe, strings,
                         circl, vt, mb, urlhaus, threatfx, otx, risk,
                         mitre=cve_det)
        if path:
            print(Fore.GREEN + f"  ✓ PDF saved: {path}" + Style.RESET_ALL)

    # JSON
    if args.json:
        output = {
            "triage_time":  started.isoformat(),
            "file":         args.filepath,
            "app_name":     app_name,
            "version":      version,
            "hashes":       hashes,
            "metadata":     {k: v for k, v in meta.items()},
            "app_category": {"primary": appcat.get("primary_category"), "matches": [m["display"] for m in appcat["matches"]]},
            "pe_analysis":  {"is_pe": pe.get("is_pe"), "suspicious_imports": pe.get("suspicious_imports",[]), "imphash": pe.get("imphash","")},
            "string_hits":  strings.get("hits",[]),
            "iocs":         {"ips": strings.get("ips",[]), "urls": strings.get("urls",[])},
            "circl":        {"known_good": circl.get("known_good")},
            "virustotal":   {"detections": vt.get("detections"), "total": vt.get("total")},
            "malwarebazaar":{"found": mb.get("found"), "family": mb.get("malware_family")},
            "urlhaus":      {"hits": len(urlhaus.get("hits",[]))},
            "threatfox":    {"hash_hit": threatfx.get("hash_hit"), "malware": threatfx.get("ioc_details",{}).get("malware")},
            "otx":          {"pulses": otx.get("pulses",0)},
            "mitre_cve":    {"total": mitre.get("total",0), "cves": [{"id": c["id"], "severity": c["severity"], "score": c["score"]} for c in mitre.get("cves",[])]},
            "nvd_cves":     {"total": cve_det.get("total",0), "cves": [{"id": c["id"], "severity": c["severity"], "score": c["score"]} for c in cve_det.get("cves",[])]},
            "risk_score":   risk,
        }
        print("\n--- JSON ---")
        print(json.dumps(output, indent=2))

    elapsed = (datetime.datetime.now() - started).total_seconds()
    print(f"\n  Completed in {elapsed:.1f}s\n")


if __name__ == "__main__":
    main()
