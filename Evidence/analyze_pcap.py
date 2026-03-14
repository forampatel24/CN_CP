import joblib
from extract_features import extract_features

MODEL_PATH = "model/attack_model.pkl"


# -----------------------------
# Behavior Detection Rules
# -----------------------------
def behavior_detection(feature_df):

    detected = {}

    unique_ports = feature_df["Unique Ports"].values[0]
    packet_rate = feature_df["Flow Packets/s"].values[0]
    packet_count = feature_df["Packet Count"].values[0]

    # Port Scan
    if unique_ports > 25 and packet_rate < 200:
        detected["PortScan"] = 0.92

    # DoS / Flood attack
    if packet_rate > 250:
        detected["DDoS"] = 0.90

    # Brute Force
    if packet_count > 40 and unique_ports <= 2:
        detected["Web Attack – Brute Force"] = 0.85

    return detected


# -----------------------------
# Main Analysis
# -----------------------------
def analyze_pcap(pcap_file):

    data = joblib.load(MODEL_PATH)

    model = data["model"]
    le = data["label_encoder"]
    features = data["features"]

    feature_df = extract_features(pcap_file)

    # ML prediction
    probs = model.predict_proba(feature_df[features])[0]
    attacks = dict(zip(le.classes_, probs))

    # Behavior detection
    behavior = behavior_detection(feature_df)

    # Merge ML + behavior results
    for k, v in behavior.items():
        attacks[k] = max(attacks.get(k, 0), v)

    print("\n===== IDS Detection Result =====\n")

    for attack, score in sorted(attacks.items(), key=lambda x: x[1], reverse=True):
        print(f"{attack}  ->  {round(score*100,2)} %")

    # Remove benign when attacks exist
    # -----------------------------
# Final Decision Logic
# -----------------------------

    benign_score = attacks.get("BENIGN", 0)

# find strongest attack
    attack_scores = {k: v for k, v in attacks.items() if k != "BENIGN"}
    top_attack = max(attack_scores, key=attack_scores.get)
    top_attack_score = attack_scores[top_attack]

# Decision rule
    if benign_score > 0.85 and top_attack_score < 0.60:
        predicted = "BENIGN"
    else:
        predicted = top_attack


# -----------------------------
# Run Script
# -----------------------------
if __name__ == "__main__":

    pcap_file = input("Enter PCAP file path: ")

    analyze_pcap(pcap_file)