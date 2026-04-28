# IT-359 Automated Network Reconnaissance & Vulnerability Assessment Tool

> 🎥 **Video Presentation:** [INSERT YOUTUBE LINK HERE]

---

## Team Members

- **Dylan Voss**
- **Grant Gollinger**

**Course:** IT-359 — Illinois State University

---

## Project Overview

This project is an automated network reconnaissance and vulnerability assessment tool designed to assist in the early stages of a penetration test. The tool automates common reconnaissance tasks such as host discovery, port scanning, service enumeration, risk identification, and AI-powered security analysis, then presents the results in a structured and readable format.

The goal of this project is to demonstrate how programming can be combined with penetration testing techniques to automate repetitive tasks, improve efficiency, and produce consistent security assessment results. Rather than relying solely on pre-built tools, this project focuses on scripting and automation to replicate a realistic penetration testing workflow.

---

## Features

- 🔍 **Automatic host discovery** via ping sweep (subnet mode)
- 🚫 **ICMP-bypass scanning** with `-Pn` for firewalled targets (single IP mode)
- 🔎 **Full TCP port scan** across all 65,535 ports
- ⚙️ **Service & version enumeration** using Nmap scripts (`-sV -sC`)
- ⚠️ **Risk identification** — flags 30+ known risky ports with descriptions
- 🤖 **AI-powered security analysis** — sends findings to Claude (Anthropic) for professional risk narrative and remediation recommendations
- 📄 **Automated report generation** — timestamped, structured output files

---

## Dependencies

| Tool | Purpose | Install |
|------|---------|---------|
| `nmap` >= 7.80 | Core scanning engine | `sudo apt install nmap` |
| `bash` >= 5.0 | Script interpreter | Pre-installed on Linux |
| `curl` | API calls to Claude | `sudo apt install curl` |
| `jq` | JSON parsing for API responses | `sudo apt install jq` |
| `grep`, `awk`, `sed` | Text parsing utilities | Pre-installed on Linux |

**Supported OS:** Ubuntu 22.04+, Ubuntu 24.04+, Kali Linux
**Not supported:** Windows (use WSL2 or a Linux VM)

---

## AI Integration Notes

This tool integrates with the **Anthropic Claude API** to generate professional AI-powered security analysis after each scan.

> ⚠️ **Important:** Only the **Anthropic Claude API** was tested and verified to work with this tool. Other AI providers (OpenAI, Gemini, Ollama, etc.) were not tested and are not supported in the current implementation. (This is a future add)

> 💳 **API Key & Cost:** The Anthropic Claude API requires a **separate paid API key** from [console.anthropic.com](https://console.anthropic.com). This is **not** included with a Claude Pro subscription — the API and the Claude.ai web interface are billed separately. A minimum credit purchase of $5 is required to get started. Each scan costs a few cents in API usage, so $5 of credits will last for hundreds of scans.

To get an API key:
1. Go to [console.anthropic.com](https://console.anthropic.com)
2. Create an account and add billing credits (minimum $5)
3. Navigate to API Keys and generate a new key
4. Use the key with the `-k` flag or set the `ANTHROPIC_API_KEY` environment variable

---

## Setup & Installation

### 1. Clone the Repository

```bash
cd ~
git clone https://github.com/dvoss26/IT-359-Group-Project.git
cd IT-359-Group-Project/src
```

### 2. Install Dependencies

```bash
sudo apt update && sudo apt install -y nmap curl jq
```

### 3. Set Your Anthropic API Key

```bash
# Set for current session only
export ANTHROPIC_API_KEY=sk-ant-YOUR_KEY_HERE

# Or add permanently to your shell profile
echo 'export ANTHROPIC_API_KEY=sk-ant-YOUR_KEY_HERE' >> ~/.bashrc
source ~/.bashrc
```

### 4. Make the Script Executable

```bash
chmod +x recon_tool.sh
```

---

## Usage

```
sudo -E ./recon_tool.sh -t <target> [-o <output_dir>] [-k <api_key>]

Options:
  -t    Target IP address or subnet (required)
  -o    Output directory for reports (default: ./reports)
  -k    Anthropic API key (or use ANTHROPIC_API_KEY env variable)
  -h    Show help
```

> **Note:** `sudo` is required because the SYN scan (`-sS`) uses raw packets. The `-E` flag preserves your environment variables (including the API key) when using sudo.

---

## Examples

### Scan a Local Subnet
Performs a ping sweep to find live hosts, then scans all of them:
```bash
sudo -E ./recon_tool.sh -t 192.168.1.0/24
```

### Scan a Single Host (e.g. Hack The Box)
Skips ping discovery and scans directly — required for firewalled hosts:
```bash
sudo -E ./recon_tool.sh -t 10.129.27.3
```

### Pass API Key Inline
```bash
sudo ./recon_tool.sh -t 10.129.27.3 -k sk-ant-YOUR_KEY_HERE
```

### Custom Output Directory
```bash
sudo -E ./recon_tool.sh -t 10.129.27.3 -o ./my_reports
```

---

## How It Works

The tool runs through 6 sequential steps:

| Step | Name | Description |
|------|------|-------------|
| 1 | Host Discovery | Ping sweep (subnet) or direct target with `-Pn` (single IP) |
| 2 | Port Scanning | Full TCP scan across all 65,535 ports (`-sS -Pn -p- -T4`) |
| 3 | Service Enumeration | Version detection and default script scan (`-sV -sC`) |
| 4 | Risk Identification | Flags 30+ known risky ports with descriptions and affected hosts |
| 5 | AI-Powered Analysis | Sends findings to Claude API for professional security narrative |
| 6 | Report Generation | Compiles all findings into timestamped output files |

---

## Output Files

Each scan creates a timestamped folder under `./reports/`:

```
reports/
└── 20260428_111856_10.129.27.3/
    ├── report.txt                  ← Main human-readable report
    ├── ai_analysis.txt             ← AI-generated security analysis
    ├── risks.txt                   ← Risk log
    ├── live_hosts.txt              ← Discovered live hosts
    ├── hosts_with_open_ports.txt   ← Hosts with open TCP ports
    ├── raw_scan.xml                ← Raw Nmap XML output
    ├── ports.gnmap                 ← Grepable port scan output
    ├── services.xml                ← Service scan XML
    └── services.txt                ← Service scan readable output
```

> ⚠️ The `reports/` directory is listed in `.gitignore` — scan results are not committed to the repository to avoid exposing sensitive target data.

---

## Sample Output

Real output generated by this tool against an authorized Hack The Box target is available in the [`data/`](data/) folder:

| File | Description |
|------|-------------|
| [`data/report.txt`](data/report.txt) | Full scan report |
| [`data/ai_analysis.txt`](data/ai_analysis.txt) | AI-generated security analysis from Claude |
| [`data/services.txt`](data/services.txt) | Raw Nmap service enumeration |
| [`data/risks.txt`](data/risks.txt) | Identified high-risk ports |

See [`data/Sample Output.md`](data/Sample%20Output.md) for full details on all sample output files.

---

## Repository Structure

```
IT-359-Group-Project/
├── .gitignore
├── README.md
├── requirements.txt
├── src/
│   └── recon_tool.sh           ← Main tool script
├── data/
│   ├── Sample Output.md        ← Index of sample output files
│   ├── report.txt              ← Sample full report
│   ├── ai_analysis.txt         ← Sample AI analysis
│   ├── services.txt            ← Sample service scan
│   ├── risks.txt               ← Sample risk log
│   └── ...                     ← Other sample output files
└── docs/
    └── IT359_Group_Project_Report.pdf  ← Final written report
```

---

## Ethical Considerations

This tool is intended **only** for use on systems you own or have explicit written permission to test. All development and testing was performed on:
- Personally owned Proxmox virtual machines running Ubuntu 22.04
- Hack The Box challenge machines (authorized penetration testing platform)

Unauthorized scanning of networks or systems is illegal and unethical. The authors accept no responsibility for misuse of this tool.

---

## Methodology

The tool follows a standard penetration testing reconnaissance workflow covering host discovery, port scanning, service enumeration, risk identification, AI-powered analysis, and report generation. Full methodology details are available in the [final writeup](docs/IT359_Group_Project_Report.pdf).
