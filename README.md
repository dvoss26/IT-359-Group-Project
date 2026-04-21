# Red Team Recon Tool — IT-359 Group Project

**Authors:** Dylan Voss & Grant Gollinger

---

## Live Demo

Add live demo YouTube link here:

---

## Project Overview

This project is an automated network reconnaissance and vulnerability assessment tool designed to assist penetration testers in the early stages of an engagement. The tool automates common recon tasks — host discovery, port scanning, service enumeration, OS detection, UDP scanning, vulnerability scripting, and risk identification — then produces a structured report with targeted mitigations and optional AI-powered threat analysis.

---

## Ethical Considerations

This tool is strictly for **authorized security testing** on systems you own or have explicit written permission to test. No public, production, or unauthorized networks should be scanned.

The tool does not perform exploitation. It is limited to reconnaissance and enumeration techniques used in the early phases of a penetration test.

Unauthorized scanning may violate the Computer Fraud and Abuse Act (CFAA) and equivalent state/international laws.

---

## Features

| Feature | Description |
|---|---|
| Host Discovery | Ping sweep for subnets; single-host mode with `-Pn` bypass for firewalled targets |
| TCP Port Scanning | Full 65535-port SYN scan with T4 timing and min-rate 1000 for practical speed |
| Service Enumeration | Version detection (`-sV`), default NSE scripts (`-sC`) |
| OS Detection | OS fingerprinting via nmap `-O` flag |
| UDP Scanning | Optional scan of 12 high-risk UDP ports (SNMP, DNS, TFTP, IKE, etc.) |
| Vuln Script Scanning | Optional `--script vuln` scan with CVE extraction |
| Risk Identification | Flags 33 known high-risk TCP ports with accurate host association |
| Targeted Mitigations | Per-port remediation advice specific to what was actually found |
| AI Threat Analysis | Claude-powered threat assessment with attack vectors and prioritized next steps |
| Structured Reports | Timestamped output directory with XML, text, and report files |

---

## Tools & Technologies

- **Language:** Bash (requires Bash 4.0+ for associative arrays)
- **Primary Scanner:** Nmap 7.80+
- **AI Integration:** Anthropic Claude API (`claude-haiku-4-5-20251001`)
- **Utilities:** grep, awk, sed, curl, jq (curl/jq required for AI mode only)
- **OS:** Linux (Ubuntu 22.04/24.04, Kali Linux); macOS with caveats (no `-sS` without root, no OS detection)

---

## Installation

```bash
# Clone the repo
git clone <repo-url>
cd IT-359-Group-Project-main

# Make the script executable
chmod +x src/recon_tool.sh

# Verify nmap is installed
nmap --version

# (Optional) Install curl and jq for AI mode
sudo apt install curl jq
```

---

## Usage

```
Usage: ./src/recon_tool.sh -t <target> [options]

Required:
  -t  Target IP address or subnet (e.g., 192.168.1.0/24 or 10.10.10.5)

Options:
  -o  Output directory for reports (default: ./reports)
  -u  Enable UDP scan on common high-risk ports
  -v  Enable vulnerability script scanning (nmap --script vuln)
  -a  Enable AI-powered threat analysis (requires ANTHROPIC_API_KEY)
  -h  Show this help message
```

### Basic scan (single host)
```bash
sudo ./src/recon_tool.sh -t 10.129.1.17
```

### Full scan with UDP, vuln scripts, and AI analysis
```bash
export ANTHROPIC_API_KEY=sk-ant-...
sudo ./src/recon_tool.sh -t 10.10.10.5 -u -v -a
```

### Subnet sweep with custom output directory
```bash
sudo ./src/recon_tool.sh -t 192.168.1.0/24 -o /tmp/pentest-results
```

> **Note:** `sudo` is required for SYN scanning (`-sS`) and OS detection (`-O`). Running without root falls back to connect-based scanning and skips OS fingerprinting.

---

## AI Integration

When run with `-a`, the tool sends your scan findings to the **Claude API** and receives a structured threat assessment covering:

1. **Threat Summary** — Overall security posture of the target
2. **Critical Findings** — Highest-severity risks with CVEs where applicable
3. **Suggested Attack Vectors** — Specific next steps with tool names and commands
4. **Prioritized Mitigations** — Remediation ordered by severity
5. **Additional Recon** — Further enumeration tools and techniques to pursue

Set your API key before running:
```bash
export ANTHROPIC_API_KEY=sk-ant-your-key-here
sudo ./src/recon_tool.sh -t <target> -a
```

Get an API key at: https://console.anthropic.com

---

## Methodology

1. **Host Discovery** — Identify live hosts via ping sweep (subnet) or assume alive (single host with `-Pn`)
2. **Port Scanning** — Full TCP SYN scan across all 65535 ports with speed tuning; optional UDP scan on 12 high-risk ports
3. **Service Enumeration** — Version detection, NSE default scripts, and OS fingerprinting on hosts with open ports
4. **Vulnerability Scanning** *(optional)* — `nmap --script vuln` with CVE extraction
5. **Risk Identification** — Flag risky ports against a 33-entry database; accurately map each risk to its affected host(s)
6. **AI Analysis** *(optional)* — Send findings to Claude API for threat assessment and attack path recommendations
7. **Report Generation** — Structured report with dynamic, per-port mitigations based on actual findings

---

## Output Structure

```
reports/
└── 20260416_142654_10.129.1.17/
    ├── report.txt              ← Final structured report
    ├── live_hosts.txt          ← Discovered hosts
    ├── raw_scan.xml            ← Full TCP port scan (XML)
    ├── ports.gnmap             ← TCP port scan (grepable)
    ├── services.xml            ← Service enumeration (XML)
    ├── services.txt            ← Service enumeration (human-readable)
    ├── os_detection.txt        ← OS fingerprint summary
    ├── risks.txt               ← Identified risk log
    ├── risky_ports_found.txt   ← Port numbers that triggered risks
    ├── udp_scan.txt            ← UDP scan results (if -u was used)
    ├── udp_ports.gnmap         ← UDP scan grepable (if -u was used)
    ├── vuln_scan.txt           ← Vuln script results (if -v was used)
    ├── vuln_scan.xml           ← Vuln script results XML (if -v was used)
    ├── cves_found.txt          ← Extracted CVEs (if -v was used)
    └── ai_analysis.txt         ← Claude threat assessment (if -a was used)
```

---

## Project Execution Plan

1. **Environment Setup** — Linux-based lab environment with Nmap and optional curl/jq
2. **Script Development** — Bash automation script using getopts for argument parsing
3. **Network Scanning** — Multi-phase scanning: host discovery → port scan → service enum → optional UDP/vuln
4. **Result Parsing** — Awk state machine for accurate per-host risk mapping across multi-host scans
5. **AI Integration** — Claude API integration with jq-based JSON construction for safe prompt embedding
6. **Report Generation** — Dynamic mitigations generated from actual findings, not static boilerplate
7. **Testing & Validation** — Tested on Hack The Box machines (Meow, etc.) in authorized lab environments
8. **Documentation & Submission** — README, sample output, and final writeup

---

## References

- [Nmap Reference Guide](https://nmap.org/book/man.html)
- [Anthropic Claude API](https://docs.anthropic.com/en/api/getting-started)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST NVD (CVE Database)](https://nvd.nist.gov/)
- [Hack The Box](https://www.hackthebox.com/) — Used for authorized testing
