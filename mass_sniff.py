
from scapy.all import sniff, Raw
import re

def packet_callback(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode('utf-8', errors='ignore')

        # Regex for common sensitive patterns
        patterns = {
            'Email': r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            'CreditCard': r"\b(?:\d[ -]*?){13,16}\b",
            'Passwords': r"(password|passwd|pwd)[=:\s]+([^&\s]+)",
        }

        for label, pattern in patterns.items():
            matches = re.findall(pattern, payload)
            if matches:
                print(f"[*] Possible {label} found: {matches}")

print("[*] Starting packet sniffing on interface eth0...")
sniff(iface="eth0", prn=packet_callback, store=0)
