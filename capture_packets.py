# live_capture.py

def capture_packets(output_file='live_packets.csv', packet_count=500, duration=None):
    print(f"[+] Starting live capture for {packet_count} packets...")

    packets = sniff(count=packet_count, timeout=duration)
    valid_packets = []

    for pkt in packets:
        if IP in pkt:
            valid_packets.append([
                pkt[IP].src,
                pkt[IP].dst,
                pkt[IP].proto,
                len(pkt)
            ])

    df = pd.DataFrame(valid_packets, columns=['src_ip', 'dst_ip', 'protocol', 'packet_len'])
    df.to_csv(output_file, index=False)
    print(f"[+] Captured and saved {len(valid_packets)} valid packets to {output_file}")
    return df
