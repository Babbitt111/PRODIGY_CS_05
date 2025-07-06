# 🛡️ Packet Sniffer Tool – Prodigy InfoTech Internship Task 5

This Python-based packet sniffer captures and analyzes live network traffic. It displays key information such as source and destination IP addresses, protocol types (TCP, UDP, ICMP), and payload data. Developed as part of my **Cyber Security Internship** at **Prodigy InfoTech**, this tool is intended strictly for educational use.

---

## ✅ Features

- Captures live packets using Scapy
- Displays:
  - Source IP address
  - Destination IP address
  - Protocol (TCP, UDP, ICMP)
  - Payload (if available)
- Real-time terminal output
- Lightweight and easy to run

---

## ⚙️ Requirements

- Python 3.x  
- Scapy library

### 📦 Install Scapy

```bash
pip install scapy

```markdown
---

## 🚀 How to Run

> ⚠️ This tool requires administrator or root privileges to capture packets.

### 🪟 On Windows:

```bash
python packet_sniffer.py

```markdown
### 🐧 On Linux/macOS:

```bash
cd ~/Documents/PRODIGYCS05
sudo python3 packet_sniffer.py

---

## 🧪 Sample Output

### 📦 TCP Packet

📦 Packet Captured: 🔹 Source IP: 192.168.1.115 🔸 Destination IP: 172.202.248.67 🔧 Protocol: TCP 📨 Payload: (some readable data)

### 📦 UDP Packet

📦 Packet Captured: 🔹 Source IP: 150.171.22.12 🔸 Destination IP: 192.168.1.115 🔧 Protocol: UDP

### 📦 ICMP Packet

📦 Packet Captured: 🔹 Source IP: 216.58.223.206 🔸 Destination IP: 192.168.1.115 🔧 Protocol: ICMP

---

## 📁 Project Structure

PRODIGYCS05/ ├── packet_sniffer.py ├── README.md └── screenshots/ ├── packet_tcp.png ├── packet_udp.png ├── packet_icmp.png

---

## 🧠 What I Learned

- How to use Scapy to capture and inspect network packets  
- How to extract IP headers, protocols, and payloads from packets  
- The importance of running network tools with elevated permissions  
- Ethical considerations when working with packet sniffing tools

---

## ⚠️ Ethical Use Disclaimer

> This tool is intended for **educational purposes only**.  
> Do not use it on networks you do not own or have explicit permission to monitor.