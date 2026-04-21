#!/bin/bash
# ============================================================
#  Red Team Recon Tool — IT-359 Group Project
#  Authors: Dylan Voss & Grant Gollinger
#  Description: Automated host discovery, port scanning,
#               service enumeration, OS detection, UDP scanning,
#               vulnerability scripting, risk identification,
#               AI-powered analysis, and report generation.
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
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║         Red Team Recon & Vulnerability Scanner           ║"
    echo "║              Dylan Voss & Grant Gollinger                ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

# ─── Usage ─────────────────────────────────────────────────
usage() {
    echo -e "Usage: ${BOLD}$0 -t <target> [options]${RESET}"
    echo ""
    echo "Required:"
    echo "  -t  Target IP address or subnet (e.g., 192.168.1.0/24 or 10.10.10.5)"
    echo ""
    echo "Options:"
    echo "  -o  Output directory for reports (default: ./reports)"
    echo "  -u  Enable UDP scan on common high-risk ports"
    echo "  -v  Enable vulnerability script scanning (nmap --script vuln)"
    echo "  -a  Enable AI-powered threat analysis (requires ANTHROPIC_API_KEY)"
    echo "  -h  Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -t 192.168.1.0/24"
    echo "  $0 -t 10.10.10.5 -u -v -a"
    echo "  $0 -t 10.129.1.17 -o /tmp/results -v"
    echo ""
    echo "AI Analysis:"
    echo "  Set ANTHROPIC_API_KEY before running with -a flag:"
    echo "  export ANTHROPIC_API_KEY=sk-ant-..."
    exit 1
}

# ─── Dependency Check ──────────────────────────────────────
check_deps() {
    echo -e "${BOLD}[*] Checking dependencies...${RESET}"
    for tool in nmap grep awk sed; do
        if ! command -v "$tool" &>/dev/null; then
            echo -e "${RED}[!] Missing required tool: $tool${RESET}"
            echo "    Install with: sudo apt install $tool"
            exit 1
        fi
    done

    if [ "$ENABLE_AI" = true ]; then
        for tool in curl jq; do
            if ! command -v "$tool" &>/dev/null; then
                echo -e "${YELLOW}[!] AI mode requires '$tool' — install with: sudo apt install $tool${RESET}"
                ENABLE_AI=false
                break
            fi
        done
        if [ "$ENABLE_AI" = true ] && [ -z "$ANTHROPIC_API_KEY" ]; then
            echo -e "${YELLOW}[!] ANTHROPIC_API_KEY is not set — disabling AI analysis.${RESET}"
            echo -e "    Set it with: export ANTHROPIC_API_KEY=sk-ant-..."
            ENABLE_AI=false
        fi
    fi

    echo -e "${GREEN}[✓] Dependencies OK.${RESET}\n"
}

# ─── Parse Arguments ───────────────────────────────────────
TARGET=""
OUTPUT_DIR="./reports"
ENABLE_UDP=false
ENABLE_VULN=false
ENABLE_AI=false

while getopts "t:o:uvah" opt; do
    case $opt in
        t) TARGET="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        u) ENABLE_UDP=true ;;
        v) ENABLE_VULN=true ;;
        a) ENABLE_AI=true ;;
        h) usage ;;
        *) usage ;;
    esac
done

[ -z "$TARGET" ] && usage

# ─── Detect Single IP vs Subnet ────────────────────────────
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
RISKY_PORTS_FOUND="$REPORT_DIR/risky_ports_found.txt"
AI_ANALYSIS="$REPORT_DIR/ai_analysis.txt"

echo -e "${BOLD}[*] Output directory : ${CYAN}$REPORT_DIR${RESET}"
echo -e "${BOLD}[*] Scan mode        : ${CYAN}$SCAN_MODE${RESET}"
echo -e "${BOLD}[*] UDP scan         : ${CYAN}$ENABLE_UDP${RESET}"
echo -e "${BOLD}[*] Vuln scan        : ${CYAN}$ENABLE_VULN${RESET}"
echo -e "${BOLD}[*] AI analysis      : ${CYAN}$ENABLE_AI${RESET}\n"

# ─── STEP 1: Host Discovery ────────────────────────────────
step1_host_discovery() {
    echo -e "${BOLD}${CYAN}[STEP 1] Host Discovery${RESET}"

    if [ "$SCAN_MODE" == "single" ]; then
        echo -e "${YELLOW}[*] Single target detected — treating host as alive (-Pn)${RESET}"
        echo "$TARGET" > "$REPORT_DIR/live_hosts.txt"
        echo -e "${GREEN}[✓] Target set: $TARGET${RESET}\n"
    else
        echo "[*] Ping sweep on subnet: $TARGET"
        nmap -sn -T4 "$TARGET" -oG - 2>/dev/null \
            | grep "Up" \
            | awk '{print $2}' \
            > "$REPORT_DIR/live_hosts.txt"

        HOST_COUNT=$(wc -l < "$REPORT_DIR/live_hosts.txt")
        if [ "$HOST_COUNT" -eq 0 ]; then
            echo -e "${RED}[!] No live hosts found. Exiting.${RESET}"
            exit 0
        fi

        echo -e "${GREEN}[✓] Found $HOST_COUNT live host(s):${RESET}"
        sed 's/^/    /' "$REPORT_DIR/live_hosts.txt"
        echo ""
    fi
}

# ─── STEP 2: Port Scanning ─────────────────────────────────
step2_port_scan() {
    echo -e "${BOLD}${CYAN}[STEP 2] Port Scanning${RESET}"

    local PN_FLAG=""
    [ "$SCAN_MODE" == "single" ] && PN_FLAG="-Pn"

    # Full TCP scan with T4 timing for practical speed
    echo "[*] Full TCP port scan (65535 ports) — T4 timing, min-rate 1000..."
    nmap -sS $PN_FLAG -p- --open -T4 --min-rate 1000 \
        -iL "$REPORT_DIR/live_hosts.txt" \
        -oX "$RAW_SCAN" \
        -oG "$REPORT_DIR/ports.gnmap" \
        2>/dev/null

    echo -e "${GREEN}[✓] TCP scan complete.${RESET}\n"

    if [ "$ENABLE_UDP" = true ]; then
        echo "[*] UDP scan on common high-risk ports..."
        # UDP scan is slow by design — targeting only the most impactful ports
        nmap -sU $PN_FLAG --open -T4 \
            -p 53,67,68,69,123,137,138,161,162,500,514,1900 \
            -iL "$REPORT_DIR/live_hosts.txt" \
            -oG "$REPORT_DIR/udp_ports.gnmap" \
            -oN "$REPORT_DIR/udp_scan.txt" \
            2>/dev/null
        echo -e "${GREEN}[✓] UDP scan complete.${RESET}\n"
    fi
}

# ─── STEP 3: Service Enumeration & OS Detection ────────────
step3_service_enum() {
    echo -e "${BOLD}${CYAN}[STEP 3] Service Enumeration & OS Detection${RESET}"

    grep "open" "$REPORT_DIR/ports.gnmap" 2>/dev/null \
        | awk '{print $2}' \
        | sort -u \
        > "$REPORT_DIR/hosts_with_open_ports.txt"

    OPEN_HOSTS=$(wc -l < "$REPORT_DIR/hosts_with_open_ports.txt")
    if [ "$OPEN_HOSTS" -eq 0 ]; then
        echo -e "${YELLOW}[!] No open ports found on any hosts. Skipping.${RESET}\n"
        return
    fi

    local PN_FLAG=""
    [ "$SCAN_MODE" == "single" ] && PN_FLAG="-Pn"

    echo "[*] Running service/version detection and OS fingerprinting..."
    nmap -sV -sC -O $PN_FLAG -T4 \
        -iL "$REPORT_DIR/hosts_with_open_ports.txt" \
        -oX "$REPORT_DIR/services.xml" \
        -oN "$REPORT_DIR/services.txt" \
        2>/dev/null

    # Extract OS detection results to a separate summary file
    if [ -f "$REPORT_DIR/services.txt" ]; then
        grep -E "^OS:|^Running:|^OS details:|^OS CPE:" "$REPORT_DIR/services.txt" \
            > "$REPORT_DIR/os_detection.txt" 2>/dev/null || true

        if [ -s "$REPORT_DIR/os_detection.txt" ]; then
            echo -e "${GREEN}[✓] OS detection results:${RESET}"
            sed 's/^/    /' "$REPORT_DIR/os_detection.txt"
        else
            echo -e "${YELLOW}[*] OS detection inconclusive (may require root or more ports).${RESET}"
        fi
    fi

    echo -e "${GREEN}[✓] Service enumeration complete.${RESET}\n"
}

# ─── STEP 4: Vulnerability Script Scanning (optional) ──────
step4_vuln_scan() {
    if [ "$ENABLE_VULN" = false ]; then return; fi

    echo -e "${BOLD}${CYAN}[STEP 4] Vulnerability Script Scanning${RESET}"
    echo -e "${YELLOW}[*] Running nmap vuln scripts — this may take several minutes...${RESET}"

    if [ ! -s "$REPORT_DIR/hosts_with_open_ports.txt" ]; then
        echo -e "${YELLOW}[!] No hosts with open ports — skipping.${RESET}\n"
        return
    fi

    local PN_FLAG=""
    [ "$SCAN_MODE" == "single" ] && PN_FLAG="-Pn"

    nmap --script vuln $PN_FLAG -T4 \
        -iL "$REPORT_DIR/hosts_with_open_ports.txt" \
        -oN "$REPORT_DIR/vuln_scan.txt" \
        -oX "$REPORT_DIR/vuln_scan.xml" \
        2>/dev/null

    # Extract any CVEs identified
    grep -oE "CVE-[0-9]{4}-[0-9]+" "$REPORT_DIR/vuln_scan.txt" \
        | sort -u \
        > "$REPORT_DIR/cves_found.txt" 2>/dev/null || true

    CVE_COUNT=$(wc -l < "$REPORT_DIR/cves_found.txt" 2>/dev/null || echo 0)
    if [ "$CVE_COUNT" -gt 0 ]; then
        echo -e "${RED}[!] $CVE_COUNT CVE(s) identified:${RESET}"
        sed 's/^/    /' "$REPORT_DIR/cves_found.txt"
    else
        echo -e "${GREEN}[✓] No CVEs found via script scan.${RESET}"
    fi
    echo ""
}

# ─── Risk & Mitigation Databases ───────────────────────────
declare -A RISKY_PORTS
RISKY_PORTS=(
    [21]="FTP — Unencrypted file transfer, credential sniffing risk"
    [22]="SSH — Brute force risk if password auth enabled; check for weak keys"
    [23]="Telnet — Unencrypted remote access, credential sniffing risk"
    [25]="SMTP — Mail relay, potential spam/phishing vector"
    [53]="DNS — Zone transfer or amplification attack risk"
    [69]="TFTP — Unauthenticated file transfer"
    [80]="HTTP — Unencrypted web traffic, check for web application vulnerabilities"
    [110]="POP3 — Unencrypted email retrieval"
    [111]="RPCbind — Remote procedure call exposure"
    [135]="MS-RPC — Windows RPC, lateral movement risk"
    [137]="NetBIOS — Legacy Windows name resolution, info disclosure"
    [139]="NetBIOS-SSN — Legacy SMB, exploitation risk"
    [143]="IMAP — Unencrypted email access"
    [161]="SNMP — Default community strings, information disclosure risk"
    [389]="LDAP — Directory service, anonymous enumeration risk"
    [443]="HTTPS — Audit for weak TLS/SSL configurations"
    [445]="SMB — EternalBlue/ransomware risk if unpatched; disable SMBv1"
    [512]="rexec — Remote execution, no encryption"
    [513]="rlogin — Legacy remote login, no encryption"
    [514]="rsh — Remote shell, no authentication"
    [1433]="MSSQL — Exposed database, brute force/injection risk"
    [1521]="Oracle DB — Exposed database service"
    [2049]="NFS — Network file share, data exposure risk"
    [3306]="MySQL — Exposed database, brute force/injection risk"
    [3389]="RDP — Remote desktop, brute force/BlueKeep/DejaBlue risk"
    [4444]="Metasploit default — Possible active backdoor or C2 listener"
    [5432]="PostgreSQL — Exposed database service"
    [5900]="VNC — Remote desktop, often weak or no authentication"
    [6379]="Redis — Often unauthenticated, arbitrary data read/write"
    [8080]="HTTP-Alt — Alternate web port, check for admin panels or proxies"
    [8443]="HTTPS-Alt — Alternate HTTPS port, verify TLS hardening"
    [9200]="Elasticsearch — Often unauthenticated, full data exposure"
    [27017]="MongoDB — Often unauthenticated, full data exposure"
)

declare -A PORT_MITIGATIONS
PORT_MITIGATIONS=(
    [21]="Disable FTP and replace with SFTP over SSH. If FTP is required, enforce FTPS (TLS) and strong credential policies."
    [22]="Disable password-based SSH authentication; require public key only. Consider non-standard port and fail2ban."
    [23]="Disable Telnet immediately. Replace with SSH for all remote access. No scenario justifies Telnet on a modern network."
    [25]="Restrict SMTP relay to authorized hosts. Enable SMTP AUTH, SPF, DKIM, and DMARC. Migrate to port 587/465."
    [53]="Restrict zone transfers to authorized secondary DNS servers only. Rate-limit DNS responses to prevent amplification."
    [69]="Disable TFTP unless required for PXE booting. If required, restrict access by IP and monitor for unauthorized transfers."
    [80]="Redirect all HTTP (80) to HTTPS (443). Enable HSTS. Test for SQLi, XSS, IDOR, and other OWASP Top 10 vulnerabilities."
    [110]="Disable POP3 (110). Require POP3S on port 995 with a valid TLS certificate."
    [111]="Block port 111 at the firewall from untrusted networks. Disable rpcbind if NFS and NIS are not in use."
    [135]="Block MS-RPC from all external access. Apply all Windows security patches to prevent RPC-based lateral movement."
    [137]="Disable NetBIOS over TCP/IP if not required for legacy applications. Block at the perimeter firewall."
    [139]="Disable SMBv1. Block NetBIOS-SSN at the firewall. Migrate fully to SMBv3 with signing enforced."
    [143]="Disable IMAP (143). Require IMAPS on port 993 with a valid TLS certificate."
    [161]="Change default SNMP community strings ('public'/'private'). Migrate to SNMPv3 with auth and privacy. Restrict to management IPs."
    [389]="Disable anonymous LDAP binds. Require LDAPS (636) or STARTTLS for all directory queries. Audit group memberships."
    [443]="Disable SSLv3, TLS 1.0, and TLS 1.1. Enforce TLS 1.2+ with strong cipher suites. Run testssl.sh or SSLyze for a full audit."
    [445]="Apply MS17-010 (EternalBlue) patch immediately if not done. Disable SMBv1. Enable SMB signing to prevent relay attacks."
    [512]="Disable rexec. It can allow unauthenticated remote execution on misconfigured systems."
    [513]="Disable rlogin. No authentication or encryption — replace with SSH."
    [514]="Disable rsh. No authentication or encryption — replace with SSH."
    [1433]="Restrict MSSQL to trusted internal IPs. Disable SA account if unused. Enforce strong authentication and minimal privilege."
    [1521]="Restrict Oracle DB to trusted hosts. Apply latest CPU patches. Audit default accounts (SCOTT, SYS, SYSTEM)."
    [2049]="Restrict NFS exports in /etc/exports to specific trusted hosts. Disable NFS if unused. Never export / or /home."
    [3306]="Bind MySQL to 127.0.0.1 unless remote access is required. Restrict remote root login. Enforce strong passwords."
    [3389]="Enforce Network Level Authentication (NLA) for RDP. Apply BlueKeep/DejaBlue patches. Place RDP behind VPN."
    [4444]="Investigate this port immediately — it is Metasploit's default listener port. Could indicate an active C2 or backdoor."
    [5432]="Bind PostgreSQL to localhost unless remote access is required. Audit pg_hba.conf for overly permissive access rules."
    [5900]="Disable VNC if unused. If required, enforce a strong VNC password and tunnel over SSH. Never expose to internet."
    [6379]="Bind Redis to 127.0.0.1. Set requirepass in redis.conf. Never expose Redis to the internet — no auth by default."
    [8080]="Review alternate HTTP port for exposed admin panels or dev servers. Apply authentication and keep software patched."
    [8443]="Apply same TLS hardening to this alternate HTTPS port as port 443. Ensure valid certificate is in use."
    [9200]="Bind Elasticsearch to localhost. Enable X-Pack security. Never expose to the internet without authentication."
    [27017]="Enable MongoDB authentication (--auth). Bind to localhost or trusted IPs. Never expose to internet without auth."
)

# ─── STEP 5: Risk Identification ───────────────────────────
# Uses an awk state machine to track current host — fixes the fragile grep -B5 approach
step5_risk_identification() {
    echo -e "${BOLD}${CYAN}[STEP 5] Risk Identification${RESET}"
    > "$RISK_LOG"
    > "$RISKY_PORTS_FOUND"

    if [ ! -f "$REPORT_DIR/services.txt" ]; then
        echo -e "${YELLOW}[!] No service data available — skipping risk analysis.${RESET}\n"
        return
    fi

    echo "[*] Analyzing open ports for known security risks..."
    RISK_COUNT=0

    # Build port→hosts map by walking services.txt with a state machine.
    # This correctly handles multi-host scans regardless of nmap output spacing.
    declare -A PORT_TO_HOSTS
    CURRENT_HOST=""
    while IFS= read -r line; do
        if [[ "$line" =~ ^"Nmap scan report for "(.+)$ ]]; then
            CURRENT_HOST="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ^([0-9]+)/tcp[[:space:]]+open ]]; then
            PORT_NUM="${BASH_REMATCH[1]}"
            if [ -n "$CURRENT_HOST" ]; then
                if [ -z "${PORT_TO_HOSTS[$PORT_NUM]+x}" ]; then
                    PORT_TO_HOSTS[$PORT_NUM]="$CURRENT_HOST"
                else
                    PORT_TO_HOSTS[$PORT_NUM]="${PORT_TO_HOSTS[$PORT_NUM]}, $CURRENT_HOST"
                fi
            fi
        fi
    done < "$REPORT_DIR/services.txt"

    for PORT in "${!RISKY_PORTS[@]}"; do
        if [ -n "${PORT_TO_HOSTS[$PORT]+x}" ]; then
            echo -e "  ${RED}[RISK]${RESET} Port ${BOLD}$PORT/tcp${RESET} — ${RISKY_PORTS[$PORT]}"
            echo -e "  ${YELLOW}  Affected: ${PORT_TO_HOSTS[$PORT]}${RESET}\n"

            echo "[RISK] Port $PORT/tcp — ${RISKY_PORTS[$PORT]}" >> "$RISK_LOG"
            echo "Affected: ${PORT_TO_HOSTS[$PORT]}" >> "$RISK_LOG"
            echo "---" >> "$RISK_LOG"
            echo "$PORT" >> "$RISKY_PORTS_FOUND"
            ((RISK_COUNT++))
        fi
    done

    # Check UDP results if scan was run
    if [ -f "$REPORT_DIR/udp_scan.txt" ]; then
        declare -A UDP_RISKY_PORTS=(
            [53]="DNS (UDP) — Zone transfer or amplification attack risk"
            [69]="TFTP (UDP) — Unauthenticated file transfer"
            [161]="SNMP (UDP) — Default community strings, information disclosure"
            [500]="IKE/IPSec (UDP) — VPN endpoint exposed, fingerprint/attack surface"
        )

        CURRENT_HOST=""
        while IFS= read -r line; do
            if [[ "$line" =~ ^"Nmap scan report for "(.+)$ ]]; then
                CURRENT_HOST="${BASH_REMATCH[1]}"
            elif [[ "$line" =~ ^([0-9]+)/udp[[:space:]]+open ]]; then
                UDP_PORT="${BASH_REMATCH[1]}"
                if [ -n "${UDP_RISKY_PORTS[$UDP_PORT]+x}" ] && [ -n "$CURRENT_HOST" ]; then
                    echo -e "  ${RED}[RISK-UDP]${RESET} Port ${BOLD}$UDP_PORT/udp${RESET} — ${UDP_RISKY_PORTS[$UDP_PORT]}"
                    echo -e "  ${YELLOW}  Affected: $CURRENT_HOST${RESET}\n"
                    echo "[RISK-UDP] Port $UDP_PORT/udp — ${UDP_RISKY_PORTS[$UDP_PORT]}" >> "$RISK_LOG"
                    echo "Affected: $CURRENT_HOST" >> "$RISK_LOG"
                    echo "---" >> "$RISK_LOG"
                    ((RISK_COUNT++))
                fi
            fi
        done < "$REPORT_DIR/udp_scan.txt"
    fi

    if [ "$RISK_COUNT" -eq 0 ]; then
        echo -e "${GREEN}[✓] No high-risk ports detected.${RESET}"
    else
        echo -e "${YELLOW}[!] $RISK_COUNT risk(s) identified.${RESET}"
    fi
    echo ""
}

# ─── STEP 6: AI-Powered Analysis (optional) ────────────────
step6_ai_analysis() {
    if [ "$ENABLE_AI" = false ]; then return; fi

    echo -e "${BOLD}${CYAN}[STEP 6] AI-Powered Threat Analysis${RESET}"
    echo "[*] Sending findings to Claude for threat assessment..."

    # Collect context for the prompt
    SERVICES_SUMMARY=""
    if [ -f "$REPORT_DIR/services.txt" ]; then
        SERVICES_SUMMARY=$(grep -E "^[0-9]+/(tcp|udp)[[:space:]]+open" \
            "$REPORT_DIR/services.txt" 2>/dev/null | head -50)
    fi

    OS_SUMMARY="Not performed or inconclusive."
    if [ -s "$REPORT_DIR/os_detection.txt" ]; then
        OS_SUMMARY=$(cat "$REPORT_DIR/os_detection.txt")
    fi

    RISKS_SUMMARY="None identified."
    if [ -s "$RISK_LOG" ]; then
        RISKS_SUMMARY=$(cat "$RISK_LOG")
    fi

    CVE_SUMMARY="Vuln scan not run or no CVEs found."
    if [ -f "$REPORT_DIR/cves_found.txt" ] && [ -s "$REPORT_DIR/cves_found.txt" ]; then
        CVE_SUMMARY=$(cat "$REPORT_DIR/cves_found.txt")
    fi

    VULN_DETAILS="Vulnerability scan not run."
    if [ -f "$REPORT_DIR/vuln_scan.txt" ] && [ -s "$REPORT_DIR/vuln_scan.txt" ]; then
        VULN_DETAILS=$(grep -A3 -E "VULNERABLE|CVE-|WARNING|State: VULNERABLE" \
            "$REPORT_DIR/vuln_scan.txt" 2>/dev/null | head -80)
        [ -z "$VULN_DETAILS" ] && VULN_DETAILS="Vuln scripts ran but found no vulnerabilities."
    fi

    PROMPT="You are a senior penetration tester reviewing an automated recon scan. Provide a focused, technical threat assessment.

TARGET: $TARGET
SCAN MODE: $SCAN_MODE

OPEN PORTS / SERVICES:
${SERVICES_SUMMARY:-No service data collected.}

OS DETECTION:
$OS_SUMMARY

IDENTIFIED RISK PORTS:
$RISKS_SUMMARY

CVEs FOUND:
$CVE_SUMMARY

VULNERABILITY SCAN DETAILS:
$VULN_DETAILS

Provide your analysis in exactly these sections:

1. THREAT SUMMARY
   A 2-3 sentence overview of the target's overall security posture.

2. CRITICAL FINDINGS
   List the most severe risks with exploitation potential (max 5, ordered by severity). Include specific CVEs where applicable.

3. SUGGESTED ATTACK VECTORS
   Concrete next steps a pentester should investigate. Be specific — reference port numbers, tool names, and commands where useful (e.g., 'enum4linux -a <ip> for SMB on 445', 'redis-cli -h <ip> for unauthenticated Redis on 6379').

4. PRIORITIZED MITIGATIONS
   Remediation steps specific to these findings, ordered from most to least critical.

5. ADDITIONAL RECON
   Recommend further enumeration tools or techniques based on what was found (e.g., gobuster/feroxbuster for HTTP, CrackMapExec for SMB, hydra for SSH brute force). Suggest specific commands where helpful.

Be technical and specific. Reference version numbers and CVEs where applicable. Do not include generic advice unrelated to the findings."

    # Use jq to safely construct the JSON payload — handles all escaping
    JSON_PAYLOAD=$(jq -n \
        --arg model "claude-haiku-4-5-20251001" \
        --argjson max_tokens 2048 \
        --arg content "$PROMPT" \
        '{model: $model, max_tokens: $max_tokens, messages: [{role: "user", content: $content}]}')

    RESPONSE=$(curl -s https://api.anthropic.com/v1/messages \
        -H "x-api-key: $ANTHROPIC_API_KEY" \
        -H "anthropic-version: 2023-06-01" \
        -H "content-type: application/json" \
        -d "$JSON_PAYLOAD" 2>/dev/null)

    API_ERROR=$(echo "$RESPONSE" | jq -r '.error.message // empty' 2>/dev/null)
    if [ -n "$API_ERROR" ]; then
        echo -e "${RED}[!] API error: $API_ERROR${RESET}"
        echo -e "${YELLOW}[!] Skipping AI analysis.${RESET}\n"
        ENABLE_AI=false
        return
    fi

    AI_TEXT=$(echo "$RESPONSE" | jq -r '.content[0].text // empty' 2>/dev/null)
    if [ -z "$AI_TEXT" ]; then
        echo -e "${YELLOW}[!] Empty response from API — check your key and network.${RESET}\n"
        ENABLE_AI=false
        return
    fi

    echo "$AI_TEXT" > "$AI_ANALYSIS"
    echo -e "${GREEN}[✓] AI analysis complete.${RESET}\n"

    echo -e "${CYAN}── AI Threat Assessment (preview) ────────────────────${RESET}"
    echo "$AI_TEXT" | head -25
    TOTAL_LINES=$(echo "$AI_TEXT" | wc -l)
    if [ "$TOTAL_LINES" -gt 25 ]; then
        echo -e "${YELLOW}  ... (${TOTAL_LINES} total lines — see $AI_ANALYSIS for full output)${RESET}"
    fi
    echo ""
}

# ─── STEP 7: Report Generation ─────────────────────────────
step7_generate_report() {
    echo -e "${BOLD}${CYAN}[STEP 7] Generating Report${RESET}"

    {
        echo "============================================================"
        echo "  RED TEAM RECONNAISSANCE & VULNERABILITY REPORT"
        echo "  Generated : $(date)"
        echo "  Target    : $TARGET"
        echo "  Scan Mode : $SCAN_MODE ($([ "$SCAN_MODE" == "single" ] && echo "single host, -Pn" || echo "subnet sweep"))"
        echo "  UDP Scan  : $ENABLE_UDP"
        echo "  Vuln Scan : $ENABLE_VULN"
        echo "  AI Analysis: $ENABLE_AI"
        echo "  Authors   : Dylan Voss & Grant Gollinger"
        echo "============================================================"
        echo ""

        # ── Section 1: Live Hosts ──
        echo "────────────────────────────────────────────────────────────"
        echo " SECTION 1: LIVE HOSTS"
        echo "────────────────────────────────────────────────────────────"
        echo "Total live hosts: $(wc -l < "$REPORT_DIR/live_hosts.txt")"
        echo ""
        cat "$REPORT_DIR/live_hosts.txt"
        echo ""

        # ── Section 2: OS Detection ──
        echo "────────────────────────────────────────────────────────────"
        echo " SECTION 2: OS DETECTION"
        echo "────────────────────────────────────────────────────────────"
        if [ -s "$REPORT_DIR/os_detection.txt" ]; then
            cat "$REPORT_DIR/os_detection.txt"
        else
            echo "OS detection inconclusive or not run (requires root for -O)."
        fi
        echo ""

        # ── Section 3: Service Enumeration ──
        echo "────────────────────────────────────────────────────────────"
        echo " SECTION 3: SERVICE ENUMERATION (TCP)"
        echo "────────────────────────────────────────────────────────────"
        if [ -f "$REPORT_DIR/services.txt" ]; then
            cat "$REPORT_DIR/services.txt"
        else
            echo "No service data collected."
        fi
        echo ""

        if [ "$ENABLE_UDP" = true ] && [ -f "$REPORT_DIR/udp_scan.txt" ]; then
            echo "────────────────────────────────────────────────────────────"
            echo " SECTION 3B: UDP SCAN RESULTS"
            echo "────────────────────────────────────────────────────────────"
            cat "$REPORT_DIR/udp_scan.txt"
            echo ""
        fi

        # ── Section 4: Identified Risks ──
        echo "────────────────────────────────────────────────────────────"
        echo " SECTION 4: IDENTIFIED RISKS"
        echo "────────────────────────────────────────────────────────────"
        if [ -s "$RISK_LOG" ]; then
            cat "$RISK_LOG"
        else
            echo "No significant risks identified."
        fi
        echo ""

        if [ "$ENABLE_VULN" = true ] && [ -f "$REPORT_DIR/vuln_scan.txt" ]; then
            echo "────────────────────────────────────────────────────────────"
            echo " SECTION 4B: VULNERABILITY SCAN RESULTS"
            echo "────────────────────────────────────────────────────────────"
            if [ -s "$REPORT_DIR/cves_found.txt" ]; then
                echo "CVEs Identified:"
                cat "$REPORT_DIR/cves_found.txt"
                echo ""
            fi
            cat "$REPORT_DIR/vuln_scan.txt"
            echo ""
        fi

        # ── Section 5: Targeted Mitigations (dynamic) ──
        echo "────────────────────────────────────────────────────────────"
        echo " SECTION 5: TARGETED MITIGATIONS"
        echo "────────────────────────────────────────────────────────────"
        if [ -s "$RISKY_PORTS_FOUND" ]; then
            echo "The following mitigations apply specifically to the risks identified above:"
            echo ""
            while IFS= read -r PORT; do
                if [ -n "${PORT_MITIGATIONS[$PORT]+x}" ]; then
                    echo "  [Port $PORT] ${RISKY_PORTS[$PORT]%%—*}"
                    echo "  → ${PORT_MITIGATIONS[$PORT]}"
                    echo ""
                fi
            done < <(sort -n "$RISKY_PORTS_FOUND" | uniq)
        else
            echo "No specific mitigations required — no high-risk ports were identified."
        fi
        echo ""

        # ── Section 6: AI Analysis ──
        if [ "$ENABLE_AI" = true ] && [ -f "$AI_ANALYSIS" ] && [ -s "$AI_ANALYSIS" ]; then
            echo "────────────────────────────────────────────────────────────"
            echo " SECTION 6: AI-POWERED THREAT ANALYSIS"
            echo "────────────────────────────────────────────────────────────"
            cat "$AI_ANALYSIS"
            echo ""
        fi

        # ── Section 7: Raw Scan Files ──
        echo "────────────────────────────────────────────────────────────"
        echo " SECTION 7: RAW SCAN FILES"
        echo "────────────────────────────────────────────────────────────"
        echo "  TCP port scan (XML) : $RAW_SCAN"
        echo "  Service scan (XML)  : $REPORT_DIR/services.xml"
        echo "  Service scan (txt)  : $REPORT_DIR/services.txt"
        echo "  Risk log            : $RISK_LOG"
        [ -f "$REPORT_DIR/udp_scan.txt" ]    && echo "  UDP scan (txt)      : $REPORT_DIR/udp_scan.txt"
        [ -f "$REPORT_DIR/vuln_scan.txt" ]   && echo "  Vuln scan (txt)     : $REPORT_DIR/vuln_scan.txt"
        [ -f "$REPORT_DIR/vuln_scan.xml" ]   && echo "  Vuln scan (XML)     : $REPORT_DIR/vuln_scan.xml"
        [ -f "$AI_ANALYSIS" ] && [ -s "$AI_ANALYSIS" ] && echo "  AI analysis         : $AI_ANALYSIS"
        echo ""

        echo "============================================================"
        echo "  END OF REPORT"
        echo "  IMPORTANT: This tool is for authorized testing only."
        echo "  Unauthorized scanning may violate federal and state laws."
        echo "============================================================"
    } > "$FINAL_REPORT"

    echo -e "${GREEN}[✓] Report saved: ${BOLD}$FINAL_REPORT${RESET}\n"
}

# ─── Main ──────────────────────────────────────────────────
main() {
    banner
    check_deps
    step1_host_discovery
    step2_port_scan
    step3_service_enum
    step4_vuln_scan
    step5_risk_identification
    step6_ai_analysis
    step7_generate_report

    echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════"
    echo -e "  Scan complete!"
    echo -e "  Report : $FINAL_REPORT"
    echo -e "════════════════════════════════════════════════════${RESET}"
}

main
