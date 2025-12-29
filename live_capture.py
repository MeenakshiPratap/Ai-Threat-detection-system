# live_capture.py

from scapy.all import sniff, IP, TCP, UDP
import pandas as pd

def extract_features(packet):
    if IP not in packet:
        return None  # Skip packets without IP layer
    
    proto = None
    sport = dport = None
    if TCP in packet:
        proto = "TCP"
        sport = packet[TCP].sport
        dport = packet[TCP].dport
    elif UDP in packet:
        proto = "UDP"
        sport = packet[UDP].sport
        dport = packet[UDP].dport

    return {
        'src_ip': packet[IP].src,
        'dst_ip': packet[IP].dst,
        'protocol': proto,
        'src_port': sport,
        'dst_port': dport,
        'packet_len': len(packet),
    }

def capture_packets(output_csv='live_packets.csv', packet_count=500):
    print(f"[+] Starting live capture for {packet_count} packets...")

    packets = sniff(count=packet_count, timeout=30)
    print(f"[+] Total packets captured (raw): {len(packets)}")

    extracted = []

    for pkt in packets:
        try:
            features = extract_features(pkt)
            if features:
                extracted.append(features)
        except Exception as e:
            print(f"[-] Error extracting packet features: {e}")

    df = pd.DataFrame(extracted)
    df.to_csv(output_csv, index=False)
    print(f"[+] Captured and saved {len(df)} valid packets to {output_csv}")

if __name__ == "__main__":
    capture_packets()
