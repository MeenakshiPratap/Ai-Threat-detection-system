def extract_features(packet):
    try:
        protocol = str(packet.proto) if hasattr(packet, 'proto') else "tcp"
        src_bytes = len(packet.payload)
        dst_bytes = 0  # Dummy value

        return {
            "protocol_type": protocol,
            "src_bytes": src_bytes,
            "dst_bytes": dst_bytes,
            "flag": "SF"  # Dummy flag
        }
    except Exception as e:
        return None
