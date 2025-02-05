# Basic-Network-Intrusion-Lab-using-Suricata

## Overview
This project is a hands-on lab designed to demonstrate how to set up a basic network intrusion detection system using Suricata. It focuses on configuring Suricata, writing custom rules, and analyzing alerts in a virtualized environment.
## Tools & Technologies
- **Suricata:** Open-source intrusion detection system.
- **Ubuntu (VM):** Host for Suricata and rule management.
- **VirtualBox:** Virtualization platform for lab setup.
- **Kali Linux (VM):** Used for generating test traffic (e.g., nmap scans, pings).

## Lab Setup
### Step 1: Create Virtual Machines
1. Set up an Ubuntu VM for Suricata and a Kali Linux VM for testing.
2. Configure network settings (e.g., bridged or NAT mode).

### Step 2: Install and Configure Suricata
- Installation:
  ```bash
  sudo apt update
  sudo apt install suricata
