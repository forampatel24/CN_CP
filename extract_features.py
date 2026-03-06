import pyshark
import pandas as pd
from collections import defaultdict

def extract_features(pcap_file):

    cap = pyshark.FileCapture(
    pcap_file,
    tshark_path=r"C:\Program Files\Wireshark\tshark.exe"
    )

    packet_times = []
    ports = set()
    total_packets = 0
    total_bytes = 0
    ssh_attempts = 0

    for packet in cap:
        try:
            total_packets += 1
            packet_times.append(packet.sniff_time)

            if hasattr(packet, 'tcp'):
                ports.add(int(packet.tcp.dstport))

                if packet.tcp.dstport == '22':
                    ssh_attempts += 1

            if hasattr(packet, 'length'):
                total_bytes += int(packet.length)

        except:
            continue

    cap.close()

    duration = (max(packet_times) - min(packet_times)).total_seconds()

    if duration == 0:
        duration = 1

    features = {
        "Destination Port": list(ports)[0] if ports else 0,
        "Flow Duration": duration,
        "Total Fwd Packets": total_packets,
        "Total Backward Packets": 0,
        "Flow Bytes/s": total_bytes / duration,
        "Flow Packets/s": total_packets / duration
    }

    statistics = {
        "unique_ports": len(ports),
        "packet_rate": total_packets / duration,
        "total_packets": total_packets,
        "ssh_attempts": ssh_attempts,
        "duration": duration,
        "start_time": min(packet_times),
        "end_time": max(packet_times)
    }

    return pd.DataFrame([features]), statistics