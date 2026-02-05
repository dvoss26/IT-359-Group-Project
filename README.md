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

## Ethical Considerations

This project was conducted strictly for educational purposes. All scans and testing were performed only on systems owned by the project members or systems where explicit authorization was granted. No public, production, or unauthorized networks were scanned.

The project does not perform exploitation or active attacks and is limited to reconnaissance and enumeration techniques commonly used in the early phases of a penetration test.

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

- **Programming Language:** Bash Scripting
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

## Project Execution Plan

The following steps outline how this project will be completed from start to finish:

1. **Environment Setup**  
   A Linux-based testing environment will be prepared using virtual machines or a private lab network. Required tools such as Nmap will be installed and verified to ensure proper functionality.

2. **Script Development**  
   A Bash script will be created using a text editor (e.g., nano) to automate the network reconnaissance process. The script will accept a target IP address or subnet as input and execute scanning commands in sequence.

3. **Network Scanning**  
   The script will perform host discovery and port scanning against the authorized target to identify live hosts, open ports, and running services.

4. **Result Parsing and Analysis**  
   Scan output will be processed to extract relevant information such as open ports and service versions. Basic logic will be applied to flag common security risks based on discovered services.

5. **Report Generation**  
   The script will generate a readable output file summarizing scan results, identified risks, and recommended mitigation steps.

6. **Testing and Validation**  
   The script will be tested multiple times in the lab environment to ensure consistent results and proper handling of different targets.

7. **Documentation and Submission**  
   Final documentation will be completed in the README file, including usage instructions, methodology, ethical considerations, and sample output. The finished project will be submitted as a GitHub repository link.

---
