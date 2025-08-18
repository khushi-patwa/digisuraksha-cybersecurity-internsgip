from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import logging
import os

# Setup logging
log_dir = "logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)
log_file = os.path.join(log_dir, "ids_alerts.log")

logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)

# Define some basic malicious signatures
signatures = [
    {"dport": 23},  # Telnet
    {"dport": 3389},  # RDP
    {"flags": "S", "dport": 80},  # SYN scan on HTTP
    {"sport": 4444},  # Backdoor default port
]

def detect_signature(packet):
    if packet.haslayer(IP):
        ip = packet[IP]
        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "OTHER"
        
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            for sig in signatures:
                match = True
                for key, value in sig.items():
                    if not hasattr(tcp, key) or getattr(tcp, key) != value:
                        match = False
                        break
                if match:
                    alert = f"[ALERT] Suspicious TCP packet from {ip.src} to {ip.dst}:{tcp.dport} | Flags: {tcp.flags}"
                    print(alert)
                    logging.info(alert)
                    return

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            for sig in signatures:
                match = True
                for key, value in sig.items():
                    if not hasattr(udp, key) or getattr(udp, key) != value:
                        match = False
                        break
                if match:
                    alert = f"[ALERT] Suspicious UDP packet from {ip.src} to {ip.dst}:{udp.dport}"
                    print(alert)
                    logging.info(alert)
                    return

def start_sniffing(interface="eth0"):
    print(f"[*] Starting Network IDS on interface {interface}...")
    sniff(iface=interface, prn=detect_signature, store=False)

if __name__ == "__main__":
    # Change "eth0" to your actual interface name, e.g., "wlan0" for Wi-Fi
    start_sniffing(interface="eth0")
