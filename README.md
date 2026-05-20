# software-triage

First-level endpoint file triage — hashes binaries, classifies application type, runs PE analysis, queries open-source threat intel APIs, searches NVD for known CVEs, and generates a scored risk PDF report. Pure Python + curl + jq, venv-isolated.

---

## What It Does

Before an end user installs anything, `software-triage` runs a fast automated first-pass across 12 steps:

| Step | What it does |
|---|---|
| 1 | MD5 / SHA1 / SHA256 + PE imphash |
| 2 | File metadata and magic byte verification (catches extension spoofing) |
| 3 | Application classification — flags RATs, VPNs, DB tools, screen sharing, and more |
| 4 | PE header analysis — architecture, compile timestamp, section entropy, imports |
| 5 | Suspicious string and IOC extraction — IPs, URLs, shell commands, registry, crypto |
| 6 | CIRCL hashlookup — instant known-good check, short-circuits further analysis |
| 7 | VirusTotal — 70+ AV engines |
| 8 | MalwareBazaar — known malware hash database |
| 9 | URLhaus — malicious URL check against extracted IOCs |
| 10 | ThreatFox — hash and IP IOC database |
| 11 | AlienVault OTX — threat pulse and campaign attribution |
| 12 | NVD CVE search — last 3 years of known vulnerabilities for the named application |

Results are aggregated into a weighted risk score (0–100) and exported as a dark-themed PDF report.

---

## Application Categories

| Category | Examples |
|---|---|
| Remote Access Tool | TeamViewer, AnyDesk, RustDesk, ConnectWise, Dameware, Bomgar |
| Session Sharing | Webex, Zoom, Microsoft Teams, GoToMeeting, Loom |
| Database Client | DBeaver, Navicat, MySQL Workbench, pgAdmin, TablePlus, Azure Data Studio |
| Cloud Collaboration | Dropbox, OneDrive, Notion, Confluence, Slack, Airtable |
| VPN / Tunneling | NordVPN, ngrok, WireGuard, Cisco AnyConnect, FortiClient, frp |
| Packet Capture | Wireshark, Burp Suite, Metasploit, nmap, Fiddler |
| Credential Tool | KeePass, Bitwarden, Hashcat, Mimikatz, LaZagne |
| Developer Tool | VS Code, Docker Desktop, Postman, Git |
| Browser | Chrome, Firefox, Edge, Brave, Tor Browser |

---

## Threat Intel Sources

| Source | Key Required | What It Checks |
|---|---|---|
| [CIRCL hashlookup](https://hashlookup.circl.lu) | No | Known-good hash — instant clean signal |
| [MalwareBazaar](https://bazaar.abuse.ch) | No | Known malware hash, family, tags |
| [URLhaus](https://urlhaus.abuse.ch) | No | Malicious URLs extracted from binary |
| [ThreatFox](https://threatfox.abuse.ch) | No | Hash and IP IOC database |
| [VirusTotal](https://www.virustotal.com) | Yes — free | 70+ AV engines |
| [AlienVault OTX](https://otx.alienvault.com) | Yes — free | Threat pulses, campaign attribution |
| [NVD / NIST](https://nvd.nist.gov) | Yes — free | CVE vulnerabilities, last 3 years |

---

## Quickstart

### 1. Clone

```bash
git clone https://github.com/your-username/software-triage.git
cd software-triage
```

### 2. Configure API keys

```bash
cp .env.example .env
nano .env
```

```env
NVD_API_KEY=your-key-here
VIRUSTOTAL_API_KEY=your-key-here
OTX_API_KEY=your-key-here
```

Free keys:
- NVD — [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)
- VirusTotal — [virustotal.com/gui/sign-in](https://www.virustotal.com/gui/sign-in)
- OTX — [otx.alienvault.com/api](https://otx.alienvault.com/api)

MalwareBazaar, URLhaus, ThreatFox, and CIRCL require no key.

### 3. Setup (one time)

```bash
bash setup.sh
```

Creates a `venv/` in the project folder and a `triage` wrapper script. No system packages modified.

### 4. Run

```bash
# Hash + intel only
./triage suspicious.exe

# With application CVE lookup
./triage setup.exe --app-name "Zoom"

# With specific version
./triage setup.exe --app-name "AnyDesk" --version "8.0.8"

# Generate PDF report (auto-named)
./triage setup.exe --app-name "TeamViewer" --pdf

# Generate PDF at specific path
./triage setup.exe --app-name "Webex" --pdf /reports/webex_triage.pdf

# JSON output for SIEM or ticketing
./triage setup.exe --app-name "Zoom" --json > report.json
```

---

## Risk Scoring

| Score | Label | Recommendation |
|---|---|---|
| 0 | CLEAN | CIRCL known-good match — approved |
| 1–29 | LOW | No major hits — standard review |
| 30–69 | MEDIUM | Investigate before permitting install |
| 70–100 | HIGH | Do not install — escalate immediately |

Score is a weighted aggregate across VT detections, MalwareBazaar, OTX pulses, URLhaus, ThreatFox, PE section entropy, suspicious imports, string matches, magic byte mismatch, and application category risk.

---

## Dependencies

- Python 3.8+
- `curl` — NVD API calls
- `jq` — NVD JSON parsing

On Arch Linux:

```bash
sudo pacman -S curl jq
```

Python packages installed automatically by `setup.sh`:

```
requests  pefile  colorama  tabulate  reportlab  beautifulsoup4
```

---

## Project Structure

```
software-triage/
├── file_triage.py     # Main tool
├── setup.sh           # One-time venv + dependency setup
├── triage             # Run wrapper (created by setup.sh)
├── .env               # Your API keys (never commit this)
├── .env.example       # Key template
├── .gitignore
├── venv/              # Isolated Python environment
└── README.md
```

---

## .gitignore

```
venv/
__pycache__/
*.pyc
*.pdf
.env
```

---

## License

GPL-3.0 — see [LICENSE](LICENSE) for details.
Free to use, modify, and distribute. Derivative works must remain open source under the same license.
