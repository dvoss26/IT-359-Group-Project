#!/bin/bash
# ============================================================
#  IT-359 Group Project — Automated Network Recon Tool
#  Authors: Dylan Voss & Grant Gollinger
#  Description: Automated host discovery, port scanning,
#               service enumeration, risk identification,
#               and report generation using Nmap + Bash.
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
    echo -e "Usage: ${BOLD}$0 -t <target> [-o <output_dir>]${RESET}"
    echo ""
    echo "  -t  Target IP address or subnet (e.g., 192.168.1.0/24 or 192.168.1.1)"
    echo "  -o  Output directory for reports (default: ./reports)"
    echo ""
    echo "Examples:"
    echo "  $0 -t 192.168.1.0/24"
    echo "  $0 -t 192.168.1.5 -o /tmp/scan_results"
    exit 1
}
 
# ─── Dependency Check ──────────────────────────────────────
check_deps() {
    echo -e "${BOLD}[*] Checking dependencies...${RESET}"
    for tool in nmap grep awk sed; do
        if ! command -v "$tool" &>/dev/null; then
            echo -e "${RED}[!] Missing required tool: $tool${RESET}"
            echo "    Install it with: sudo apt install $tool"
            exit 1
        fi
    done
    echo -e "${GREEN}[✓] All dependencies found.${RESET}\n"
}
 
# ─── Parse Arguments ───────────────────────────────────────
TARGET=""
OUTPUT_DIR="./reports"
 
while getopts "t:o:h" opt; do
    case $opt in
        t) TARGET="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
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
 
echo -e "${BOLD}[*] Output will be saved to: ${CYAN}$REPORT_DIR${RESET}\n"
 
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
        echo " SECTION 5: RAW SCAN FILES"
        echo "────────────────────────────────────────────────────────────"
        echo "  Raw XML scan data: $RAW_SCAN"
        echo "  Service scan:      $REPORT_DIR/services.xml"
        echo "  Risk log:          $RISK_LOG"
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
    step5_generate_report
 
    echo -e "${BOLD}${GREEN}════════════════════════════════════════════════════"
    echo -e "  Scan complete! Full report: $FINAL_REPORT"
    echo -e "════════════════════════════════════════════════════${RESET}"
}
 
main
