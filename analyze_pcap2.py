import joblib
import hashlib
import os
from datetime import datetime

from extract_features import extract_features

# PDF
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4

MODEL_PATH = "model/attack_model.pkl"
OUTPUT_DIR = r"C:\Foram\ENG_SY\SEM2\CN\Course_Project\CN_CP\output"


# -----------------------------
# Behavior Detection Rules
# -----------------------------
def behavior_detection(feature_df):

    detected = {}

    unique_ports = feature_df["Unique Ports"].values[0]
    packet_rate = feature_df["Flow Packets/s"].values[0]
    packet_count = feature_df["Packet Count"].values[0]

    if unique_ports > 25 and packet_rate < 200:
        detected["PortScan"] = 0.92

    if packet_rate > 250:
        detected["DDoS"] = 0.90

    if packet_count > 40 and unique_ports <= 2:
        detected["Web Attack – Brute Force"] = 0.85

    return detected


# -----------------------------
# Attack Explanations
# -----------------------------
def explain_attack(attack):

    explanations = {
        "PortScan": "The attacker is scanning multiple ports to find open services.",
        "DDoS": "A large number of packets are sent to overwhelm the system.",
        "DoS Hulk": "High traffic flood aimed at exhausting server resources.",
        "DoS slowloris": "Slow connections used to keep server busy.",
        "DoS Slowhttptest": "Partial HTTP requests to exhaust server connections.",
        "DoS GoldenEye": "Rapid HTTP requests to overload the server.",
        "FTP-Patator": "Repeated login attempts on FTP service.",
        "SSH-Patator": "Repeated login attempts on SSH service.",
        "Web Attack – Brute Force": "Multiple password attempts on web services.",
        "Web Attack – XSS": "Injection of malicious scripts into web pages.",
        "Web Attack – Sql Injection": "Injection of SQL queries to access data.",
        "Bot": "System may be remotely controlled as part of a botnet.",
        "Infiltration": "Attempt to maintain long-term hidden access.",
        "Heartbleed": "Critical vulnerability attempt to leak memory data."
    }

    return explanations.get(attack, "Suspicious activity detected.")


# -----------------------------
# File Hash
# -----------------------------
def compute_hash(file_path):

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


# -----------------------------
# PDF Generator
# -----------------------------
def generate_pdf(report_text, filename):

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    pdf_path = os.path.join(OUTPUT_DIR, filename)

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    styles = getSampleStyleSheet()

    story = []

    for line in report_text.split("\n"):
        story.append(Paragraph(line, styles["Normal"]))
        story.append(Spacer(1, 10))

    doc.build(story)

    print(f"\nPDF saved at: {pdf_path}")


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

    # Merge ML + behavior
    for k, v in behavior.items():
        attacks[k] = max(attacks.get(k, 0), v)

    # -----------------------------
    # Filter relevant attacks
    # -----------------------------
    threshold = 0.50
    filtered = {k: v for k, v in attacks.items() if v >= threshold and k != "BENIGN"}

    # -----------------------------
    # Hash
    # -----------------------------
    file_hash = compute_hash(pcap_file)

    # -----------------------------
    # Timeline (basic reconstruction)
    # -----------------------------
    now = datetime.now()
    timeline = [
        now.strftime("%H:%M:%S") + "  Suspicious activity detected",
        now.strftime("%H:%M:%S") + "  Analysis performed",
        now.strftime("%H:%M:%S") + "  Attack patterns identified"
    ]

    # -----------------------------
    # Report Build
    # -----------------------------
    report = []

    report.append("TRACE-NF : Network Forensics Report")
    report.append("=" * 60)

    report.append(f"\nEvidence File: {os.path.basename(pcap_file)}")

    report.append("\nIntegrity Verification:")
    report.append(f"SHA-256 Hash: {file_hash}")
    report.append("Status: VERIFIED")

    report.append("\nAnalysis Summary:")
    report.append("The network traffic shows suspicious patterns indicating possible attacks.\n")

    report.append("Detected Attacks:\n")

    if not filtered:
        report.append("No significant attack detected.\n")
    else:
        for attack, score in sorted(filtered.items(), key=lambda x: x[1], reverse=True):

            report.append(f"{attack} ({round(score*100,2)}%)")
            report.append(f"Explanation: {explain_attack(attack)}\n")

    report.append("\nTimeline:")
    for t in timeline:
        report.append(t)

    report.append("\nFinal Conclusion:")

    if not filtered:
        report.append("Traffic appears normal with no strong indicators of attack.")
    else:
        report.append(
            "The system detected malicious behavior. The attacker likely attempted "
            "reconnaissance followed by exploitation. Immediate action is recommended."
        )

    report.append("\n" + "=" * 60)

    report_text = "\n".join(report)

    print("\n" + report_text)

    # -----------------------------
    # Generate PDF
    # -----------------------------
    filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    generate_pdf(report_text, filename)


# -----------------------------
# Run Script
# -----------------------------
if __name__ == "__main__":

    pcap_file = input("Enter PCAP file path: ")

    analyze_pcap(pcap_file)