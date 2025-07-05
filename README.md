# LANRecon – Python LAN Scanner with Version Detection and CVE Lookup

LANRecon is a multithreaded Python tool that scans a local IPv4 network to:

- Detect live hosts
- Scan open TCP ports
- Detect running services and their versions (via Nmap)
- Generate links to possible vulnerabilities (CVEs) from [Vulners.com](https://vulners.com)

---

## Features

- Fast multithreaded host discovery (ping sweep)
- Port scanning with custom range
- Nmap-based service and version detection
- Automatic CVE search link generation
- No API keys required (uses Vulners web search)

---

## Files

- `LANrecon.py` – Main script file (Python 3)

---

## Requirements

- Python 3.6+
- `nmap` installed on your system

### 🔧 Install Nmap (Linux)

```bash
sudo apt install nmap
