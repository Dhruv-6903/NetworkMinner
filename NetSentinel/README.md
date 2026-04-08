# NetSentinel

> **Passive network forensics, actively working for you.**

NetSentinel is a desktop forensic tool inspired by NetworkMiner. It passively analyses network traffic from PCAP files or live interfaces and reconstructs everything: hosts, sessions, credentials, files, DNS activity, and automatic alerts — all inside a professional dark-themed PyQt5 GUI.

---

## Table of Contents

1. [Features](#features)
2. [Requirements](#requirements)
3. [Installation](#installation)
4. [Running the tool](#running-the-tool)
5. [Optional: GeoIP database](#optional-geoip-database)
6. [Optional: VirusTotal API key](#optional-virustotal-api-key)
7. [Usage walkthrough](#usage-walkthrough)
8. [Project structure](#project-structure)
9. [Packaging into a Windows executable](#packaging-into-a-windows-executable)
10. [Troubleshooting](#troubleshooting)

---

## Features

| Tab | What it shows |
|-----|---------------|
| **Hosts** | Every IP/MAC seen in traffic — hostname, OS guess (passive fingerprinting), country, bytes sent/received, open ports |
| **Sessions** | TCP/UDP/ICMP flows with 5-tuple, duration, byte counts, flags. Double-click to inspect the raw stream |
| **Credentials** | Cleartext credentials from FTP, HTTP Basic Auth, HTTP Form POST, Telnet, SMTP AUTH, POP3, IMAP — all highlighted red |
| **Files** | Files reconstructed from HTTP responses (with chunked + gzip support), TFTP. MD5 hash + VirusTotal status |
| **DNS** | Every DNS query and response. Automatic tagging for tunnelling, DGA domains, beaconing, NXDomain |
| **Alerts** | Rule-based alerts: port scans, ICMP floods, credential capture, large file transfers, brute force, malicious hashes |

Additional capabilities:
- **Live capture** via Scapy (requires root/administrator)
- **GeoIP enrichment** with MaxMind GeoLite2 (offline, no rate limits)
- **VirusTotal** file hash lookups (rate-limited to 4 req/min)
- **Export**: CSV per tab, full JSON report, ZIP archive of extracted files
- **Dark theme** throughout (customisable via `gui/styles/theme.qss`)
- **Real-time filter bars** in every tab
- **Right-click context menus**: copy IP, filter, VirusTotal, Shodan
- **Mask passwords** option for screen sharing

---

## Requirements

- Python 3.9 or newer
- Windows 10/11 or Linux (macOS secondary)
- For live capture on Linux: **root privileges** (`sudo python main.py`)
- For live capture on Windows: **run as Administrator**

---

## Installation

### Step 1 — Clone or download the repository

```bash
git clone https://github.com/Dhruv-6903/NetworkMinner.git
cd NetworkMinner/NetSentinel
```

### Step 2 — Create a virtual environment (recommended)

```bash
python -m venv venv

# Activate on Linux / macOS
source venv/bin/activate

# Activate on Windows
venv\Scripts\activate
```

### Step 3 — Install dependencies

```bash
pip install -r requirements.txt
```

> **Note for Windows users:** If PyQt5 installation fails, try:
> ```bash
> pip install PyQt5==5.15.10 --only-binary :all:
> ```

> **Note for Linux users:** You may need system packages for Scapy's live capture:
> ```bash
> sudo apt-get install libpcap-dev python3-dev
> ```

---

## Running the tool

```bash
# From inside the NetSentinel/ folder:
python main.py
```

For live capture on Linux, run with root:

```bash
sudo venv/bin/python main.py
```

---

## Optional: GeoIP database

NetSentinel supports offline GeoIP enrichment using the free MaxMind GeoLite2-City database.

1. Create a free account at [https://www.maxmind.com](https://www.maxmind.com)
2. Download **GeoLite2-City.mmdb** from your MaxMind account dashboard
3. Place the file anywhere accessible (e.g. `NetSentinel/assets/GeoLite2-City.mmdb`)
4. In NetSentinel, open **Settings → GeoIP DB** and select the `.mmdb` file
5. Country and city columns in the Hosts tab will populate on next analysis

---

## Optional: VirusTotal API key

1. Register at [https://www.virustotal.com](https://www.virustotal.com)
2. Copy your free API key from your profile
3. In NetSentinel, open **Settings → VT API Key** and paste the key
4. Extracted files will automatically be queued for hash lookup (rate-limited to 4 req/min)

---

## Usage walkthrough

### Loading a PCAP file

1. Launch NetSentinel
2. Click **📂 Load PCAP** in the toolbar
3. Select a `.pcap` or `.pcapng` file
4. Watch all six tabs populate in real time
5. Click any row for detailed information in the detail panel

### Live capture

1. Select a network interface from the dropdown
2. Optionally enter a BPF filter expression (e.g. `tcp port 80`)
3. Click **▶ Start Capture**
4. Click **■ Stop** when done

### Exporting results

Click **⬇ Export** in the toolbar and choose:

- **Export CSV (all tabs)** — saves `Hosts.csv`, `Sessions.csv`, etc. to a folder you select
- **Export JSON report** — saves a single nested JSON file
- **Export extracted files (ZIP)** — packages all reconstructed files with a `manifest.csv`

### Settings

Click **⚙ Settings** to configure:

- VirusTotal API key
- GeoIP database path
- Output directory
- Mask passwords (shows `••••••••` instead of real passwords — useful for demos)

---

## Project structure

```
NetSentinel/
├── main.py                  ← Entry point
├── requirements.txt
├── README.md
│
├── core/                    ← Pure Python backend (no GUI imports)
│   ├── pcap_loader.py       ← PCAP/PCAPNG reading (dpkt), single-pass dispatch
│   ├── live_capture.py      ← Scapy AsyncSniffer live capture
│   ├── host_extractor.py    ← Host inventory, OS fingerprinting, TLS SNI
│   ├── session_tracker.py   ← TCP/UDP flow reconstruction, 5-tuple keying
│   ├── credential_harvester.py  ← FTP, HTTP, Telnet, SMTP, POP3, IMAP
│   ├── dns_parser.py        ← DNS queries/responses, DGA entropy detection
│   ├── file_extractor.py    ← HTTP/TFTP file reconstruction
│   ├── alert_engine.py      ← Rule-based alert generation
│   └── threat_intel.py      ← VirusTotal API + GeoIP2 lookups
│
├── gui/                     ← PyQt5 UI layer
│   ├── main_window.py       ← Main window, toolbar, workers, signal wiring
│   ├── tabs/
│   │   ├── hosts_tab.py
│   │   ├── sessions_tab.py
│   │   ├── credentials_tab.py
│   │   ├── files_tab.py
│   │   ├── dns_tab.py
│   │   └── alerts_tab.py
│   ├── widgets/
│   │   ├── detail_panel.py  ← Expandable detail view
│   │   ├── filter_bar.py    ← Real-time filter widget
│   │   └── status_bar.py    ← Live stats bar
│   └── styles/
│       └── theme.qss        ← Dark Qt stylesheet
│
├── output/
│   ├── exporter.py          ← CSV / JSON / ZIP export
│   └── extracted_files/     ← Reconstructed files land here
│
├── assets/
│   └── icons/               ← Application icons
│
└── config/
    └── settings.py          ← User preferences (~/.netsentinel/settings.json)
```

---

## Packaging into a Windows executable

Install PyInstaller (already in requirements.txt), then:

```bash
pyinstaller --onefile --windowed --name NetSentinel main.py
```

The executable will be created at `dist/NetSentinel.exe`.

For better packaging, include the theme stylesheet and assets:

```bash
pyinstaller --onefile --windowed --name NetSentinel \
  --add-data "gui/styles/theme.qss;gui/styles" \
  --add-data "assets;assets" \
  main.py
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError: No module named 'PyQt5'` | Run `pip install -r requirements.txt` inside the virtual environment |
| Live capture button is greyed out (Linux) | Run the tool with `sudo` |
| GeoIP lookup shows no country data | Set the GeoIP DB path in Settings |
| VirusTotal status stays "Pending" | Set a valid VT API key in Settings |
| PCAP loading is slow | Normal for large files — the progress bar shows completion percentage |
| `ImportError` on Scapy | Install libpcap: `sudo apt-get install libpcap-dev` |

---

## License

This project is for educational and professional security research purposes.
Always obtain proper authorisation before capturing network traffic.
