import pyshark
import pandas as pd
import numpy as np


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
                if packet.tcp.flags_fin == "1":
                    fin_count += 1
                if packet.tcp.flags_push == "1":
                    psh_count += 1

        except:
            continue

    cap.close()

    # -----------------------------
    # Basic derived statistics
    # -----------------------------

    unique_ports = len(ports)

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
    packet_var = np.var(packet_lengths) if packet_lengths else 0

    min_pkt = min(packet_lengths) if packet_lengths else 0
    max_pkt = max(packet_lengths) if packet_lengths else 0

    avg_packet_size = total_bytes / total_packets if total_packets else 0

    fwd_mean = fwd_bytes / fwd_packets if fwd_packets else 0
    bwd_mean = bwd_bytes / bwd_packets if bwd_packets else 0

    # -----------------------------
    # Inter-arrival times
    # -----------------------------

    if len(packet_times) > 1:
        iat = np.diff([t.timestamp() for t in packet_times])
        flow_iat_mean = np.mean(iat)
        flow_iat_std = np.std(iat)
        flow_iat_max = np.max(iat)
        flow_iat_min = np.min(iat)
    else:
        flow_iat_mean = flow_iat_std = flow_iat_max = flow_iat_min = 0

    # -----------------------------
    # Build feature vector
    # -----------------------------

    features = {

        "Destination Port": np.mean(list(ports)) if ports else 0,

        "Flow Duration": duration,

        "Total Fwd Packets": fwd_packets + unique_ports,
        "Total Length of Fwd Packets": fwd_bytes,

        "Fwd Packet Length Max": max_pkt,
        "Fwd Packet Length Min": min_pkt,
        "Fwd Packet Length Mean": fwd_mean,
        "Fwd Packet Length Std": packet_std,

        "Bwd Packet Length Max": max_pkt,
        "Bwd Packet Length Min": min_pkt,
        "Bwd Packet Length Mean": bwd_mean,
        "Bwd Packet Length Std": packet_std,

        "Flow Bytes/s": byte_rate,
        "Flow Packets/s": packet_rate,

        "Flow IAT Mean": flow_iat_mean,
        "Flow IAT Std": flow_iat_std,
        "Flow IAT Max": flow_iat_max,
        "Flow IAT Min": flow_iat_min,

        "Fwd IAT Total": duration,
        "Fwd IAT Mean": duration / fwd_packets if fwd_packets else 0,
        "Fwd IAT Std": 0,
        "Fwd IAT Max": duration,
        "Fwd IAT Min": 0,

        "Bwd IAT Total": duration,
        "Bwd IAT Mean": duration / bwd_packets if bwd_packets else 0,
        "Bwd IAT Std": 0,
        "Bwd IAT Max": duration,
        "Bwd IAT Min": 0,

        "Fwd Header Length": 0,
        "Bwd Header Length": 0,

        "Fwd Packets/s": fwd_packets / duration if duration else 0,
        "Bwd Packets/s": bwd_packets / duration if duration else 0,

        "Min Packet Length": min_pkt,
        "Max Packet Length": max_pkt,
        "Packet Length Mean": packet_mean,
        "Packet Length Std": packet_std,
        "Packet Length Variance": packet_var,

        "FIN Flag Count": fin_count,
        "PSH Flag Count": psh_count,
        "ACK Flag Count": ack_count,

        "Average Packet Size": avg_packet_size,

        "Subflow Fwd Bytes": fwd_bytes,

        "Init_Win_bytes_forward": 0,
        "Init_Win_bytes_backward": 0,

        "act_data_pkt_fwd": fwd_packets,
        "min_seg_size_forward": min_pkt,

        "Active Mean": duration,
        "Active Max": duration,
        "Active Min": duration,

        "Idle Mean": 0,
        "Idle Max": 0,
        "Idle Min": 0
    }

    # Additional features for behavioral detection
    features["Unique Ports"] = unique_ports
    features["Packet Count"] = total_packets

    return pd.DataFrame([features])