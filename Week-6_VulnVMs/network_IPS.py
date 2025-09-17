from scapy.all import sniff, IP, TCP, UDP, Raw
import logging
import time
import threading

# Configure logging to file
logging.basicConfig(filename="ips_alerts.log", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

# Define simple attack signatures (could be expanded)
SIGNATURES = {
    "SYN_FLOOD": {
        "description": "Possible SYN Flood attack",
        "pattern": None,  # we'll detect based on TCP flags & frequency
        "threshold": 100,  # number of SYN packets per second per source IP
    },
    "MALICIOUS_PAYLOAD": {
        "description": "Malicious payload detected",
        "pattern": [b"malware", b"attack", b"exploit"],  # example malicious keywords in payload
    }
}

# Track SYN packets per source IP for rate limiting
syn_packet_count = {}

# Lock for thread-safe updates
lock = threading.Lock()

def detect_syn_flood(pkt):
    """Detect SYN flood by counting SYN packets per source IP."""
    if TCP in pkt and pkt[TCP].flags == 'S':  # SYN flag only
        src_ip = pkt[IP].src
        with lock:
            count = syn_packet_count.get(src_ip, 0)
            syn_packet_count[src_ip] = count + 1

def reset_syn_counts():
    """Reset SYN counts every second."""
    while True:
        time.sleep(1)
        with lock:
            for ip, count in list(syn_packet_count.items()):
                if count > SIGNATURES["SYN_FLOOD"]["threshold"]:
                    alert = f"SYN Flood detected from IP {ip} with {count} SYN packets in last second."
                    logging.warning(alert)
                    print(alert)
                syn_packet_count[ip] = 0

def check_payload(pkt):
    """Check packet payload for malicious patterns."""
    if Raw in pkt:
        payload = pkt[Raw].load.lower()
        for pattern in SIGNATURES["MALICIOUS_PAYLOAD"]["pattern"]:
            if pattern in payload:
                alert = f"Malicious payload detected from {pkt[IP].src} to {pkt[IP].dst}. Pattern: {pattern.decode()}"
                logging.warning(alert)
                print(alert)
                # Here you could block/drop the packet if possible (simulation)
                return True
    return False

def packet_handler(pkt):
    """Process each packet."""
    if IP in pkt:
        # Detect SYN flood attempts
        detect_syn_flood(pkt)

        # Check for malicious payloads
        if check_payload(pkt):
            # Drop packet logic would go here - simulated by not forwarding or alerting
            pass

def main():
    print("Starting Network IPS... Press Ctrl+C to stop.")
    # Start thread to reset SYN counters and detect floods
    threading.Thread(target=reset_syn_counts, daemon=True).start()

    # Sniff packets on the default interface, filtering IP traffic
    sniff(filter="ip", prn=packet_handler, store=False)

if __name__ == "__main__":
    main()
