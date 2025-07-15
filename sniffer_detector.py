
import psutil

def detect_sniffing():
    print("[*] Scanning for suspicious sniffers...")
    suspicious = []
    sniff_signatures = ['scapy', 'tcpdump', 'wireshark', 'sniff']

    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if any(sig in ' '.join(proc.info['cmdline']) for sig in sniff_signatures):
                suspicious.append((proc.info['pid'], proc.info['name']))
        except:
            continue

    if suspicious:
        print("[!] Potential sniffers detected:")
        for pid, name in suspicious:
            print(f"  PID: {pid}, Name: {name}")
    else:
        print("[+] No sniffers detected.")

if __name__ == "__main__":
    detect_sniffing()
