# software-triage

First-level endpoint file triage — hashes binaries, classifies app type (RAT, VPN, DB, screen sharing), queries VirusTotal, MalwareBazaar, URLhaus, ThreatFox & CIRCL, and outputs a scored risk PDF. Pure Python, venv-isolated.

---

## What It Does

Before an end user installs anything, `software-triage` runs a fast, automated first-pass analysis:

- **Hashes the file** — MD5, SHA1, SHA256, and PE imphash
- **Detects file type** — magic byte verification catches extension spoofing
- **Classifies the application** — flags Remote Access Tools, VPN/tunneling clients, database tools, screen sharing apps, packet capture utilities, and credential managers before anything runs
- **Extracts IOCs** — pulls embedded IPs, URLs, and domains from the binary
- **Queries 6 open-source threat intel APIs** — no proprietary infrastructure required
- **Scores risk 0–100** — weighted aggregate across all findings
- **Generates a PDF report** — dark-themed, analyst-ready, suitable for ticketing or escalation

---

## Application Categories

| Category | Examples |
|---|---|
| Remote Access Tool | TeamViewer, AnyDesk, RustDesk, ConnectWise, Dameware |
| Session Sharing | Webex, Zoom, Microsoft Teams, GoToMeeting, Loom |
| Database Client | DBeaver, Navicat, MySQL Workbench, pgAdmin, TablePlus |
| Cloud Collaboration | Dropbox, OneDrive, Notion, Confluence, Slack |
| VPN / Tunneling | NordVPN, ngrok, WireGuard, Cisco AnyConnect, frp |
| Packet Capture | Wireshark, Burp Suite, Metasploit, nmap |
| Credential Tool | KeePass, Bitwarden, Hashcat, Mimikatz |
| Developer Tool | VS Code, Docker Desktop, Postman, Git |
| Browser | Chrome, Firefox, Edge, Brave, Tor Browser |

---

## Threat Intel APIs

| Source | Requires Key | Checks |
|---|---|---|
| [CIRCL hashlookup](https://hashlookup.circl.lu) | No | Known-good hash — instant clean signal |
| [MalwareBazaar](https://bazaar.abuse.ch) | No | Known malware hash, family, tags |
| [URLhaus](https://urlhaus.abuse.ch) | No | Malicious URLs extracted from binary |
| [ThreatFox](https://threatfox.abuse.ch) | No | Hash and IP IOC database |
| [VirusTotal](https://www.virustotal.com) | Yes (free) | 70+ AV engines |
| [AlienVault OTX](https://otx.alienvault.com) | Yes (free) | Threat pulses and campaign attribution |

---

## Quickstart

### 1. Clone

```bash
git clone https://github.com/your-username/software-triage.git
cd software-triage
```

### 2. Setup (one time)

```bash
bash setup.sh
```

Creates a `.venv` inside the project folder and a `triage` wrapper script. No system packages modified.

### 3. Run

```bash
# Basic
./triage suspicious.exe

# With PDF report (auto-named)
./triage setup.exe --pdf

# With PDF at specific path
./triage setup.exe --pdf /reports/setup_triage.pdf

# Also emit JSON
./triage setup.exe --pdf --json
```

### 4. API Keys (optional but recommended)

```bash
export VIRUSTOTAL_API_KEY=your_key_here
export OTX_API_KEY=your_key_here

./triage setup.exe --pdf
```

Add exports to `~/.bashrc` or `~/.zshrc` to persist across sessions. Free keys at [virustotal.com](https://www.virustotal.com/gui/sign-in) and [otx.alienvault.com](https://otx.alienvault.com/api).

---

## Risk Scoring

| Score | Label | Recommendation |
|---|---|---|
| 0 | CLEAN | CIRCL known-good match — approved |
| 1–29 | LOW | No major hits — standard review |
| 30–69 | MEDIUM | Investigate before permitting install |
| 70–100 | HIGH | Do not install — escalate immediately |

Score is a weighted aggregate across: VT detections, MalwareBazaar hit, OTX pulses, URLhaus URLs, ThreatFox IOCs, PE entropy, suspicious imports, string pattern matches, magic byte mismatch, and application category risk.

---

## Output

```
  ┌─────────────────────┬──────────────────────────────────────┐
  │ File                │ TeamViewer_Setup.exe                 │
  │ Detected Type       │ PE/EXE (Windows Executable)          │
  │ App Category        │ Remote Access Tool (RAT / RMM)       │
  │ Policy Note         │ HIGH POLICY RISK — full remote ctrl  │
  │ CIRCL Known-Good    │ Unknown                              │
  │ VT Detections       │ 0/72 engines                         │
  │ MalwareBazaar       │ Not listed                           │
  │ URLhaus             │ Clean                                │
  │ ThreatFox           │ Not listed                           │
  │ Suspicious Imports  │ 3                                    │
  │ RISK SCORE          │ MEDIUM (score: 35/100)               │
  └─────────────────────┴──────────────────────────────────────┘

  ▶ CAUTION — Investigate before permitting installation.
```

---

## Requirements

- Python 3.8+
- Arch Linux / any distro (venv-isolated, no system packages needed)
- Internet access for API queries

Dependencies installed automatically by `setup.sh`:

```
requests  pefile  colorama  tabulate  reportlab
```

---

## Project Structure

```
software-triage/
├── file_triage.py     # Main tool
├── setup.sh           # One-time venv + dependency setup
├── triage             # Run wrapper (created by setup.sh)
├── .venv/             # Isolated Python environment
└── README.md
```

---

## License

MIT
