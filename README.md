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
1. Set up an Ubuntu VM for Suricata, Firewall/NAT/DHCP and a Kali Linux VM for testing. (I did plan on using a Windows VM as well but decided to hold off until I am ready to do more work with this project that is why in the third photo you see a Desktop when I checked the status of the DHCP server) 
2. Configure network settings (e.g., bridged or NAT mode). The Unbuntu VM had a NAT connection as well as a internal network connection, and the Kali VM had just the internal network connection.
- After setting up the VMs I went and added a few firewall rules to the iptables. Thes first rule enables IP masquerading for packets leaving the system through eth0
  ```bash
      sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
- The next rule allows incoming traffic from eth1 to be forwarded to eth0, but only if it’s part of an established or related connection
  ```bash
  sudo iptables -A FORWARD -i eth1 -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
- The final rule allows outgoing traffic from eth0 (internet or external network) to be forwarded to eth1 (internal network)
  ```bash
   sudo iptables -A FORWARD -i eth0 -o eth1 -j ACCEPT
- The attached photo shows the current iptables
![VirtualBox_Ubuntu Firewall_05_02_2025_08_05_16](https://github.com/user-attachments/assets/e7a8b934-644b-47b0-ac34-3aee36d64148)


- During network setup I had to Modify the configuration to assign a static IP to the LAN interface (in this case it was the internal network connection)

![VirtualBox_Ubuntu Firewall_05_02_2025_07_55_52](https://github.com/user-attachments/assets/1afcea81-c210-46c1-b0db-3706001449a9)

   
- In this step I also edited the configurations for enp0s3 and enp0s8 on my ubuntu VM using the command
  ```bash
  sudo nano /etc/netplan/00-installer-config.yaml"
- as well as install the ISC DHCP server
  ```bash
  sudo apt update, sudo apt install isc-dhcp-server

![Systemctl status](https://github.com/user-attachments/assets/77929757-7093-4951-884a-09f9016aef21)

- and configure the dhcp settings using the command
  ```bash
  sudo nano /etc/dhcp/dhcpd.conf
 ![sudo nano conf](https://github.com/user-attachments/assets/b3d1234a-785e-4537-8926-6a1286964aec)


### Step 2: Install and Configure Suricata
- Installation:
  ```bash
  sudo apt update
  sudo apt install suricata -y
 - Once installed I ran the following command to edit the configurations so the Suricata interface would be on the same as my Ubuntu interface (in this case enp0s8)
   ```bash
   sudo nano /etc/suricata/suricata.yaml
 - I proceeded to allow Suricata to start upon start up using 
    ```bash
    sudo systemctl enable suricata
 - As well as the following command to start Suricata 
    ```bash
    sudo systemctl start suricata
 - Once I knew the service was up and running the Local rules file using 
    ```bash
    sudo nano /etc/suricata/rules/local.rules
  I added the following commands
 -  This rule detects any Ping Traffic made 
    ```bash
    alert icmp any any -> any any (msg:"ICMP Echo Request Detected"; sid:1000001; rev:1;) This rule detects any Ping Traffic made 
 - This rule detects Nmap Scans
   ```bash
   alert tcp any any -> any any (flags:S; msg:"Nmap SYN Scan Detected"; threshold:type both, track by_src, count 5, seconds 2; sid:1000002; rev:1;) 
 - This rule detects Port Scans in General
   ```bash
   alert tcp any any -> any any (msg:"TCP Port Scan Detected"; flags:S; threshold:type both, track by_src, count 20, seconds 10; sid:1000003; rev:1;) 
 - This rule detects any SSH login attempts
    ```bash
   alert tcp any any -> any 22 (msg:"SSH Login Attempt Detected"; flow:to_server,established; sid:1000004; rev:1;) 
 - This final rule is used to help detect any HTTP traffic
   ```bash
   alert http any any -> any any (msg:"HTTP Traffic Detected"; sid:1000005; rev:1;) 

 - The attached Image shows a preview of Pings I sent from my Kali vm HTTP traffic as well as a Nmap scan I ran with my Kali machine as well
     ![c0FL6Pg - Imgur](https://github.com/user-attachments/assets/f7d4b026-0e88-4cad-a8da-713efadd6b65)







