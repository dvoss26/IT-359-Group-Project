#!/bin/bash
# ============================================================
#  IT-359 Group Project — Automated Network Recon Tool
#  Authors: Dylan Voss & Grant Gollinger
#  Description: Automated host discovery, port scanning,
#               service enumeration, risk identification,
#               AI-powered analysis, and report generation
#               using Nmap, Bash, and the Claude API.
# ============================================================

# ─── Colors ────────────────────────────────────────────────
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

# ─── Banner ────────────────────────────────────────────────
banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════╗"
    echo "║       IT-359 Network Recon & Vuln Scanner        ║"
    echo "║         Dylan Voss & Grant Gollinger             ║"
    echo "╚══════════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

# ─── Usage ─────────────────────────────────────────────────
usage() {
    echo -e "Usage: ${BOLD}$0 -t <target> [-o <output_dir>] [-k <api_key>]${RESET}"
    echo ""
    echo "  -t  Target IP address or subnet (e.g., 192.168.1.0/24 or 192.168.1.1)"
    echo "  -o  Output directory for reports (default: ./reports)"
    echo "  -k  Anthropic API key (or set ANTHROPIC_API_KEY env variable)"
    echo ""
    echo "Examples:"
    echo "  $0 -t 192.168.1.0/24 -k sk-ant-..."
    echo "  ANTHROPIC_API_KEY=sk-ant-... $0 -t 10.10.10.5"
    exit 1
}

# ─── Dependency Check ──────────────────────────────────────
check_deps() {
    echo -e "${BOLD}[*] Checking dependencies...${RESET}"
    for tool in nmap grep awk sed curl jq; do
        if ! command -v "$tool" &>/dev/null; then
            echo -e "${RED}[!] Missing required tool: $tool${RESET}"
            echo "    Install it with: sudo apt install $tool"
            exit 1
        fi
    done
    if [ -z "$ANTHROPIC_API_KEY" ]; then
        echo -e "${RED}[!] No Anthropic API key found.${RESET}"
        echo "    Pass it with -k <key> or set ANTHROPIC_API_KEY env variable."
        echo "    Example: export ANTHROPIC_API_KEY=sk-ant-..."
        exit 1
    fi
    echo -e "${GREEN}[✓] All dependencies found.${RESET}\n"
}

# ─── Parse Arguments ───────────────────────────────────────
TARGET=""
OUTPUT_DIR="./reports"
USE_AI=true

while getopts "t:o:k:h" opt; do
    case $opt in
        t) TARGET="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        k) ANTHROPIC_API_KEY="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

[ -z "$TARGET" ] && usage

# ─── Detect Single IP vs Subnet ────────────────────────────
# If the target contains a CIDR prefix (e.g. /24), it's a subnet.
# Otherwise treat it as a single host and skip ping discovery.
if [[ "$TARGET" == *"/"* ]]; then
    SCAN_MODE="subnet"
else
    SCAN_MODE="single"
fi

# ─── Setup Output Directory ────────────────────────────────
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORT_DIR="${OUTPUT_DIR}/${TIMESTAMP}_${TARGET//\//_}"
mkdir -p "$REPORT_DIR"

RAW_SCAN="$REPORT_DIR/raw_scan.xml"
FINAL_REPORT="$REPORT_DIR/report.txt"
RISK_LOG="$REPORT_DIR/risks.txt"
AI_ANALYSIS="$REPORT_DIR/ai_analysis.txt"

echo -e "${BOLD}[*] Output will be saved to: ${CYAN}$REPORT_DIR${RESET}"
echo -e "${BOLD}[*] AI analysis: ${GREEN}ENABLED${RESET} (Claude API)"
echo ""

# ─── STEP 6: AI-Powered Analysis ───────────────────────────
step6_ai_analysis() {
    if [ "$USE_AI" = false ]; then
        return
    fi

    echo -e "${BOLD}${CYAN}[STEP 6] AI-Powered Analysis (Claude)${RESET}"
    echo "[*] Sending scan findings to Claude for analysis..."

    # Build a concise summary of findings to send to the API
    SERVICES_SUMMARY=""
    if [ -f "$REPORT_DIR/services.txt" ]; then
        # Extract just the open port lines — keep the prompt focused and small
        SERVICES_SUMMARY=$(grep -E "^[0-9]+/tcp.*open" "$REPORT_DIR/services.txt" | head -40)
    fi

    RISKS_SUMMARY=""
    if [ -s "$RISK_LOG" ]; then
        RISKS_SUMMARY=$(cat "$RISK_LOG")
    fi

    if [ -z "$SERVICES_SUMMARY" ]; then
        echo -e "${YELLOW}[!] No service data to analyze. Skipping AI step.${RESET}\n"
        return
    fi

    # Build the prompt — structured so Claude returns clearly formatted sections
    PROMPT="You are a professional penetration tester writing a vulnerability assessment report section.

The following data was collected by an automated Nmap scan against target: ${TARGET}

=== OPEN PORTS & SERVICES ===
${SERVICES_SUMMARY}

=== IDENTIFIED RISK FLAGS ===
${RISKS_SUMMARY}

Please provide a professional security analysis with the following sections:

1. EXECUTIVE SUMMARY
   A 3-4 sentence non-technical summary of the overall risk posture of this target.

2. DETAILED FINDINGS
   For each significant open port/service found, provide:
   - What the service is and what it does
   - The specific security risk it presents in this context
   - The potential impact if exploited
   - A CVSS risk rating (Critical/High/Medium/Low) with brief justification

3. ATTACK SURFACE ANALYSIS
   Describe the overall attack surface — what an attacker would prioritize targeting first and why.

4. REMEDIATION RECOMMENDATIONS
   Specific, actionable remediation steps ordered by priority (highest risk first).

5. CONCLUSION
   A brief concluding paragraph summarizing overall security posture and recommended next steps.

Write in a professional tone suitable for a penetration testing report. Be specific to the services actually found — do not give generic advice."

    # Escape the prompt for JSON using jq
    PROMPT_JSON=$(jq -n --arg content "$PROMPT" '$content')

    # Call the Anthropic Messages API
    RESPONSE=$(curl -s \
        "https://api.anthropic.com/v1/messages" \
        --header "x-api-key: ${ANTHROPIC_API_KEY}" \
        --header "anthropic-version: 2023-06-01" \
        --header "content-type: application/json" \
        --data "{
            \"model\": \"claude-opus-4-5\",
            \"max_tokens\": 2000,
            \"messages\": [
                {\"role\": \"user\", \"content\": ${PROMPT_JSON}}
            ]
        }")

    # Check for API errors
    API_ERROR=$(echo "$RESPONSE" | jq -r '.error.message // empty' 2>/dev/null)
    if [ -n "$API_ERROR" ]; then
        echo -e "${RED}[!] Claude API error: $API_ERROR${RESET}"
        echo -e "${YELLOW}[!] Skipping AI analysis. Check your API key and try again.${RESET}\n"
        return
    fi

    # Extract the text content from the response
    AI_TEXT=$(echo "$RESPONSE" | jq -r '.content[0].text // empty' 2>/dev/null)

    if [ -z "$AI_TEXT" ]; then
        echo -e "${RED}[!] No response received from Claude API.${RESET}\n"
        return
    fi

    # Save AI analysis to its own file
    {
        echo "============================================================"
        echo "  AI-POWERED SECURITY ANALYSIS"
        echo "  Generated by Claude (Anthropic)"
        echo "  Target: $TARGET  |  $(date)"
        echo "============================================================"
        echo ""
        echo "$AI_TEXT"
        echo ""
        echo "============================================================"
        echo "  END OF AI ANALYSIS"
        echo "============================================================"
    } > "$AI_ANALYSIS"

    echo -e "${GREEN}[✓] AI analysis complete. Saved to: ${BOLD}$AI_ANALYSIS${RESET}\n"
}

# ─── STEP 1: Host Discovery ────────────────────────────────
step1_host_discovery() {
    echo -e "${BOLD}${CYAN}[STEP 1] Host Discovery${RESET}"

    if [ "$SCAN_MODE" == "single" ]; then
        # Single IP — skip ping, assume host is up (handles HTB/firewalled hosts)
        echo -e "${YELLOW}[*] Single target detected — skipping ping sweep (treating host as alive)${RESET}"
        echo -e "[*] Note: Using -Pn to bypass ICMP blocks (common on HTB and firewalled hosts)"
        echo "$TARGET" > "$REPORT_DIR/live_hosts.txt"
        echo -e "${GREEN}[✓] Target set: $TARGET${RESET}\n"
    else
        # Subnet — do a normal ping sweep to find live hosts
        echo "[*] Scanning for live hosts on subnet: $TARGET"

        nmap -sn "$TARGET" -oG - 2>/dev/null \
            | grep "Up" \
            | awk '{print $2}' \
            > "$REPORT_DIR/live_hosts.txt"

        HOST_COUNT=$(wc -l < "$REPORT_DIR/live_hosts.txt")

        if [ "$HOST_COUNT" -eq 0 ]; then
            echo -e "${RED}[!] No live hosts found. Exiting.${RESET}"
            exit 0
        fi

        echo -e "${GREEN}[✓] Found $HOST_COUNT live host(s):${RESET}"
        cat "$REPORT_DIR/live_hosts.txt" | sed 's/^/    /'
        echo ""
    fi
}

# ─── STEP 2: Port Scanning ─────────────────────────────────
step2_port_scan() {
    echo -e "${BOLD}${CYAN}[STEP 2] Port Scanning${RESET}"
    echo "[*] Running full TCP port scan (this may take a moment)..."

    if [ "$SCAN_MODE" == "single" ]; then
        # -Pn skips host discovery, treats target as always up (needed for HTB)
        nmap -sS -Pn -p- --open \
            -iL "$REPORT_DIR/live_hosts.txt" \
            -oX "$RAW_SCAN" \
            -oG "$REPORT_DIR/ports.gnmap" \
            2>/dev/null
    else
        nmap -sS -p- --open \
            -iL "$REPORT_DIR/live_hosts.txt" \
            -oX "$RAW_SCAN" \
            -oG "$REPORT_DIR/ports.gnmap" \
            2>/dev/null
    fi

    echo -e "${GREEN}[✓] Port scan complete.${RESET}\n"
}

# ─── STEP 3: Service Enumeration ───────────────────────────
step3_service_enum() {
    echo -e "${BOLD}${CYAN}[STEP 3] Service Enumeration${RESET}"
    echo "[*] Enumerating services and versions on open ports..."

    # Extract open ports per host from gnmap
    grep "open" "$REPORT_DIR/ports.gnmap" \
        | awk '{print $2}' \
        | sort -u \
        > "$REPORT_DIR/hosts_with_open_ports.txt"

    OPEN_HOSTS=$(wc -l < "$REPORT_DIR/hosts_with_open_ports.txt")

    if [ "$OPEN_HOSTS" -eq 0 ]; then
        echo -e "${YELLOW}[!] No open ports found on any hosts.${RESET}\n"
        return
    fi

    if [ "$SCAN_MODE" == "single" ]; then
        nmap -sV -sC -Pn \
            -iL "$REPORT_DIR/hosts_with_open_ports.txt" \
            -oX "$REPORT_DIR/services.xml" \
            -oN "$REPORT_DIR/services.txt" \
            2>/dev/null
    else
        nmap -sV -sC \
            -iL "$REPORT_DIR/hosts_with_open_ports.txt" \
            -oX "$REPORT_DIR/services.xml" \
            -oN "$REPORT_DIR/services.txt" \
            2>/dev/null
    fi

    echo -e "${GREEN}[✓] Service enumeration complete.${RESET}\n"
}

# ─── STEP 4: Risk Identification ───────────────────────────
# Define risky ports and what they indicate
declare -A RISKY_PORTS
RISKY_PORTS=(
    [21]="FTP — Unencrypted file transfer, credential sniffing risk"
    [23]="Telnet — Unencrypted remote access, credential sniffing risk"
    [25]="SMTP — Mail relay, potential spam/phishing vector"
    [53]="DNS — Zone transfer or amplification attack risk"
    [69]="TFTP — Unauthenticated file transfer"
    [80]="HTTP — Unencrypted web traffic"
    [110]="POP3 — Unencrypted email retrieval"
    [111]="RPCbind — Remote procedure call exposure"
    [135]="MS-RPC — Windows RPC, lateral movement risk"
    [137]="NetBIOS — Legacy Windows name resolution"
    [139]="NetBIOS-SSN — Legacy SMB, exploitation risk"
    [143]="IMAP — Unencrypted email access"
    [161]="SNMP — Default community strings, info disclosure"
    [389]="LDAP — Directory service, enumeration risk"
    [443]="HTTPS — Check for weak TLS/SSL configs"
    [445]="SMB — EternalBlue/ransomware risk if unpatched"
    [512]="rexec — Remote execution, no encryption"
    [513]="rlogin — Legacy remote login, no encryption"
    [514]="rsh — Remote shell, no authentication"
    [1433]="MSSQL — Exposed database service"
    [1521]="Oracle DB — Exposed database service"
    [2049]="NFS — Network file share, potential data exposure"
    [3306]="MySQL — Exposed database service"
    [3389]="RDP — Remote desktop, brute force/BlueKeep risk"
    [4444]="Metasploit default — Possible backdoor/C2"
    [5432]="PostgreSQL — Exposed database service"
    [5900]="VNC — Remote desktop, often weak auth"
    [6379]="Redis — Often unauthenticated, data exposure"
    [8080]="HTTP-Alt — Alternate web port, check for admin panels"
    [8443]="HTTPS-Alt — Alternate HTTPS, check TLS"
    [9200]="Elasticsearch — Often unauthenticated, data exposure"
    [27017]="MongoDB — Often unauthenticated, data exposure"
)

step4_risk_identification() {
    echo -e "${BOLD}${CYAN}[STEP 4] Risk Identification${RESET}"
    > "$RISK_LOG"

    if [ ! -f "$REPORT_DIR/services.txt" ]; then
        echo -e "${YELLOW}[!] No service data found, skipping risk analysis.${RESET}\n"
        return
    fi

    echo "[*] Analyzing open ports for known security risks..."
    RISK_COUNT=0

    for PORT in "${!RISKY_PORTS[@]}"; do
        # Search for the port in the nmap output
        MATCHES=$(grep -E "^[0-9]+/tcp.*open" "$REPORT_DIR/services.txt" \
                  | grep "^${PORT}/tcp" 2>/dev/null)

        if [ -n "$MATCHES" ]; then
            # Find which hosts have this port open
            HOSTS_WITH_PORT=$(grep -B5 "^${PORT}/tcp" "$REPORT_DIR/services.txt" \
                              | grep "Nmap scan report" \
                              | awk '{print $NF}' \
                              | tr -d '()')

            echo -e "  ${RED}[RISK]${RESET} Port ${BOLD}$PORT${RESET} — ${RISKY_PORTS[$PORT]}"
            echo "  Affected host(s): $HOSTS_WITH_PORT" 2>/dev/null || true
            echo ""

            echo "[RISK] Port $PORT — ${RISKY_PORTS[$PORT]}" >> "$RISK_LOG"
            echo "Affected: $HOSTS_WITH_PORT" >> "$RISK_LOG"
            echo "---" >> "$RISK_LOG"
            ((RISK_COUNT++))
        fi
    done

    if [ "$RISK_COUNT" -eq 0 ]; then
        echo -e "${GREEN}[✓] No high-risk ports detected.${RESET}"
    else
        echo -e "${YELLOW}[!] $RISK_COUNT risk(s) identified. See report for details.${RESET}"
    fi
    echo ""
}

# ─── STEP 5: Report Generation ─────────────────────────────
step5_generate_report() {
    echo -e "${BOLD}${CYAN}[STEP 5] Generating Report${RESET}"

    {
        echo "============================================================"
        echo "  IT-359 NETWORK RECONNAISSANCE & VULNERABILITY REPORT"
        echo "  Generated: $(date)"
        echo "  Target:    $TARGET"
        echo "  Scan Mode: $SCAN_MODE ($([ "$SCAN_MODE" == "single" ] && echo "single host, ping disabled (-Pn)" || echo "subnet sweep"))"
        echo "  Authors:   Dylan Voss & Grant Gollinger"
        echo "============================================================"
        echo ""

        echo "────────────────────────────────────────────────────────────"
        echo " SECTION 1: LIVE HOSTS"
        echo "────────────────────────────────────────────────────────────"
        echo "Total live hosts found: $(wc -l < "$REPORT_DIR/live_hosts.txt")"
        echo ""
        cat "$REPORT_DIR/live_hosts.txt"
        echo ""

        echo "────────────────────────────────────────────────────────────"
        echo " SECTION 2: SERVICE ENUMERATION"
        echo "────────────────────────────────────────────────────────────"
        if [ -f "$REPORT_DIR/services.txt" ]; then
            cat "$REPORT_DIR/services.txt"
        else
            echo "No service data collected."
        fi
        echo ""

        echo "────────────────────────────────────────────────────────────"
        echo " SECTION 3: IDENTIFIED RISKS"
        echo "────────────────────────────────────────────────────────────"
        if [ -s "$RISK_LOG" ]; then
            cat "$RISK_LOG"
        else
            echo "No significant risks identified."
        fi
        echo ""

        echo "────────────────────────────────────────────────────────────"
        echo " SECTION 4: MITIGATION RECOMMENDATIONS"
        echo "────────────────────────────────────────────────────────────"
        echo "General recommendations based on findings:"
        echo ""
        echo "  • Disable or firewall any unencrypted services (FTP, Telnet, rsh, rlogin)"
        echo "  • Replace unencrypted protocols with secure alternatives (SFTP, SSH)"
        echo "  • Ensure all database services (MySQL, MSSQL, MongoDB, Redis) require authentication"
        echo "    and are not exposed to the network unnecessarily"
        echo "  • Apply latest security patches for SMB, RDP, and Windows RPC services"
        echo "  • Review and harden SNMP community strings or disable SNMP if unused"
        echo "  • Audit NFS and Samba shares for unnecessary public access"
        echo "  • Consider placing all non-essential services behind a firewall or VPN"
        echo "  • Review TLS/SSL configurations on HTTPS services for weak ciphers"
        echo ""

        echo "────────────────────────────────────────────────────────────"
        echo " SECTION 5: AI-POWERED ANALYSIS"
        echo "────────────────────────────────────────────────────────────"
        if [ -s "$AI_ANALYSIS" ]; then
            cat "$AI_ANALYSIS"
        else
            echo "AI analysis was not generated. Check your API key and connectivity."
        fi
        echo ""

        echo "────────────────────────────────────────────────────────────"
        echo " SECTION 6: RAW SCAN FILES"
        echo "────────────────────────────────────────────────────────────"
        echo "  Raw XML scan data: $RAW_SCAN"
        echo "  Service scan:      $REPORT_DIR/services.xml"
        echo "  Risk log:          $RISK_LOG"
        echo "  AI analysis:       $AI_ANALYSIS"
        echo ""

        echo "============================================================"
        echo "  END OF REPORT"
        echo "============================================================"
    } > "$FINAL_REPORT"

    echo -e "${GREEN}[✓] Report saved to: ${BOLD}$FINAL_REPORT${RESET}\n"
}

# ─── Main ──────────────────────────────────────────────────
main() {
    banner
    check_deps
    step1_host_discovery
    step2_port_scan
    step3_service_enum
    step4_risk_identification
    step6_ai_analysis
    step5_generate_report

    echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════"
    echo -e "  Scan complete! Full report: $FINAL_REPORT"
    echo -e "  AI analysis:  $AI_ANALYSIS"
    echo -e "════════════════════════════════════════════════════${RESET}"
}

main
