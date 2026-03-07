import pyshark
import pandas as pd
import numpy as np
from collections import defaultdict


def extract_features(pcap_file):

    cap = pyshark.FileCapture(
        pcap_file,
        tshark_path=r"C:\Program Files\Wireshark\tshark.exe",
        keep_packets=False
    )

    packet_times = []
    packet_lengths = []

    ports = set()

    fwd_packets = 0
    bwd_packets = 0

    fwd_bytes = 0
    bwd_bytes = 0

    syn_count = 0
    ack_count = 0
    rst_count = 0
    fin_count = 0
    psh_count = 0

    src_ip = None

    for packet in cap:
        try:

            packet_times.append(packet.sniff_time)

            length = int(packet.length)
            packet_lengths.append(length)

            if hasattr(packet, "ip"):

                if src_ip is None:
                    src_ip = packet.ip.src

                if packet.ip.src == src_ip:
                    fwd_packets += 1
                    fwd_bytes += length
                else:
                    bwd_packets += 1
                    bwd_bytes += length

            if hasattr(packet, "tcp"):

                ports.add(int(packet.tcp.dstport))

                if packet.tcp.flags_syn == "1":
                    syn_count += 1
                if packet.tcp.flags_ack == "1":
                    ack_count += 1
                if packet.tcp.flags_rst == "1":
                    rst_count += 1
                if packet.tcp.flags_fin == "1":
                    fin_count += 1
                if packet.tcp.flags_push == "1":
                    psh_count += 1

        except:
            continue

    cap.close()

    if len(packet_times) > 1:
        duration = (max(packet_times) - min(packet_times)).total_seconds()
    else:
        duration = 1

    if duration <= 0:
        duration = 1

    total_packets = fwd_packets + bwd_packets
    total_bytes = fwd_bytes + bwd_bytes

    packet_rate = total_packets / duration
    byte_rate = total_bytes / duration

    packet_mean = np.mean(packet_lengths) if packet_lengths else 0
    packet_std = np.std(packet_lengths) if packet_lengths else 0

    fwd_mean = fwd_bytes / fwd_packets if fwd_packets > 0 else 0
    bwd_mean = bwd_bytes / bwd_packets if bwd_packets > 0 else 0

    avg_packet_size = total_bytes / total_packets if total_packets > 0 else 0

    # ----------------------------
    # ML Feature Vector (MATCH TRAIN MODEL)
    # ----------------------------

    features = {

        "Destination Port": list(ports)[0] if ports else 0,

        "Flow Duration": duration,

        "Total Fwd Packets": fwd_packets,

        "Total Backward Packets": bwd_packets,

        "Total Length of Fwd Packets": fwd_bytes,

        "Total Length of Bwd Packets": bwd_bytes,

        "Flow Bytes/s": byte_rate,

        "Flow Packets/s": packet_rate,

        "Packet Length Mean": packet_mean,

        "Packet Length Std": packet_std,

        "Fwd Packet Length Mean": fwd_mean,

        "Bwd Packet Length Mean": bwd_mean,

        "FIN Flag Count": fin_count,

        "SYN Flag Count": syn_count,

        "RST Flag Count": rst_count,

        "PSH Flag Count": psh_count,

        "ACK Flag Count": ack_count,

        "Average Packet Size": avg_packet_size,

        "Active Mean": duration,

        "Idle Mean": 0
    }

    statistics = {

        "unique_ports": len(ports),
        "packet_rate": packet_rate,
        "total_packets": total_packets,
        "duration": duration,
        "start_time": min(packet_times) if packet_times else "Unknown",
        "end_time": max(packet_times) if packet_times else "Unknown",
        "source_ip": src_ip if src_ip else "Unknown",
        "ssh_attempts": sum(1 for p in ports if p == 22),
        "syn_count": syn_count,

        "ack_count": ack_count
    }

    return pd.DataFrame([features]), statistics