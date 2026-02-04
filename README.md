# IT-359-Group-Project
Repository for the IT 359 Group Project led by Dylan Voss and Grant Gollinger.

## Team Members
- Team Member 1: Dylan Voss
- Team Member 2: Grant Gollinger

---

## Project Overview

This project is an automated network reconnaissance and vulnerability assessment tool designed to assist in the early stages of a penetration test. The tool automates common reconnaissance tasks such as host discovery, port scanning, service enumeration, and basic risk identification, then presents the results in a structured and readable format.

The goal of this project is to demonstrate how programming can be combined with penetration testing techniques to automate repetitive tasks, improve efficiency, and produce consistent security assessment results. Rather than relying solely on pre-built tools, this project focuses on scripting and automation to replicate a realistic penetration testing workflow.

---

## Project Objectives

The primary objectives of this project are:
- To automate network reconnaissance tasks using custom scripts
- To demonstrate practical penetration testing concepts such as scanning and enumeration
- To analyze scan results and identify potential security risks
- To generate readable output that includes mitigation recommendations
- To follow ethical and legal standards for security testing

---

## Tools & Technologies Used

- **Programming Language:** Bash
- **Primary Security Tool:** Nmap
- **Operating System:** Linux
- **Additional Utilities:** grep, awk, sed

---

## Methodology

The tool follows a standard penetration testing reconnaissance workflow:

1. **Host Discovery**  
   The script identifies live hosts within a specified IP address or subnet using network scanning techniques.

2. **Port Scanning**  
   Open TCP ports are identified to determine which services may be accessible on discovered hosts.

3. **Service Enumeration**  
   Service names and version information are collected to better understand the exposed attack surface.

4. **Risk Identification**  
   Based on discovered services and ports, the script flags common security concerns such as:
   - Unencrypted services (e.g., FTP, Telnet)
   - Exposed database services
   - Legacy or high-risk ports

5. **Report Generation**  
   Scan results are formatted into a readable output file summarizing findings and recommended mitigations.

---

## Ethical Considerations

This project was conducted strictly for educational purposes. All scans and testing were performed only on systems owned by the project members or systems where explicit authorization was granted. No public, production, or unauthorized networks were scanned.

The project does not perform exploitation or active attacks and is limited to reconnaissance and enumeration techniques commonly used in the early phases of a penetration test.

---

## Usage Instructions

1. Ensure required tools are installed:
   - Nmap
   - Bash or Python environment

2. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/network-recon-tool.git
   cd network-recon-tool
