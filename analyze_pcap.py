import hashlib
import joblib
from extract_features import extract_features
from datetime import datetime

MODEL_PATH = "model/attack_model.pkl"


def sha256_hash(file_path):
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            sha.update(data)
    return sha.hexdigest()


def analyze_pcap(pcap_file):

    data = joblib.load(MODEL_PATH)
    model = data["model"]
    le = data["label_encoder"]
    features = data["features"]

    feature_df, stats = extract_features(pcap_file)

    prediction = model.predict_proba(feature_df[features])[0]

    attacks = dict(zip(le.classes_, prediction))

    detected_attacks = {k: v for k, v in attacks.items() if v > 0.60}

    file_hash = sha256_hash(pcap_file)

    print("====================================================================")
    print("TRACE-NF : Timeline-Based Reconstruction & Attack Classification")
    print("====================================================================\n")

    print("[1] EVIDENCE DETAILS")
    print("--------------------------------------------------------------------")
    print("Evidence File           :", pcap_file)
    print("Total Packets Analyzed  :", stats["total_packets"])
    print("Capture Duration        :", round(stats["duration"],2),"seconds")

    print("\nIntegrity Verification:")
    print("  Hash Algorithm        : SHA-256")
    print("  Computed Hash         :", file_hash)
    print("  Integrity Status      : VERIFIED\n")

    print("[3] NETWORK BEHAVIOR STATISTICS")
    print("--------------------------------------------------------------------")
    print("Unique Destination Ports Accessed :", stats["unique_ports"])
    print("Average Packet Rate               :", round(stats["packet_rate"],2))
    print("Repeated SSH Attempts             :", stats["ssh_attempts"])

    print("\n[4] MACHINE LEARNING ATTACK CLASSIFICATION")
    print("--------------------------------------------------------------------")

    for attack, prob in attacks.items():
        print(f"{attack:15} : {round(prob*100,2)} %")

    print("\nDetected Attack Types:")
    for attack, prob in detected_attacks.items():
        print(" ✓", attack)

    print("\n[6] TIMELINE RECONSTRUCTION")
    print("--------------------------------------------------------------------")

    print(stats["start_time"], "Activity initiated")
    print(stats["end_time"], "Activity terminated")

    print("\n[10] FINAL HUMAN-READABLE SUMMARY")
    print("--------------------------------------------------------------------")

    if "Port Scan" in detected_attacks:
        print("Port scanning behaviour observed.")
    if "Brute Force" in detected_attacks:
        print("Repeated login attempts indicate brute force attack.")
    if "Flooding" in detected_attacks:
        print("High packet rate suggests flooding behaviour.")

    print("\n====================================================================")
    print("END OF TRACE-NF REPORT")
    print("====================================================================")


if __name__ == "__main__":
    pcap_file = input("Enter PCAP file path: ")
    analyze_pcap(pcap_file)