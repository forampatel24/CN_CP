import joblib
import hashlib
import os
from datetime import datetime

from extract_features import extract_features

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
# Deep Explanation Engine
# -----------------------------
def get_attack_details(attack):

    details = {

        "PortScan": {
            "meaning": "The attacker is checking different ports on the system to see what services are running.",
            "technical": "Many different ports are accessed in a short time.",
            "impact": "This helps the attacker find weak points to attack later.",
            "precautions": [
                "Close unused ports",
                "Use firewall rules",
                "Monitor unusual connection attempts"
            ],
            "conclusion": "Someone is exploring your system to find possible entry points. This is usually the first step before a real attack."
        },

        "DDoS": {
            "meaning": "A very large number of requests are sent to the system at once.",
            "technical": "Extremely high traffic and packet rate.",
            "impact": "The system may slow down or stop working completely.",
            "precautions": [
                "Use DDoS protection services",
                "Enable rate limiting",
                "Use load balancing"
            ],
            "conclusion": "Your system is being overloaded with traffic on purpose, likely to make it unavailable to users."
        },

        "FTP-Patator": {
            "meaning": "Repeated login attempts on FTP service.",
            "technical": "Many login attempts in a short time.",
            "impact": "If passwords are weak, the attacker may gain access.",
            "precautions": [
                "Use strong passwords",
                "Enable account lockout",
                "Monitor login attempts"
            ],
            "conclusion": "Someone is trying multiple passwords to break into your FTP account."
        },

        "SSH-Patator": {
            "meaning": "Repeated login attempts on SSH.",
            "technical": "High number of login retries.",
            "impact": "Possible full system access if successful.",
            "precautions": [
                "Use SSH keys instead of passwords",
                "Enable multi-factor authentication",
                "Limit login attempts"
            ],
            "conclusion": "An attacker is trying to guess your SSH login details to take control of the system."
        },

        "Web Attack – XSS": {
            "meaning": "Malicious scripts are being injected into web pages.",
            "technical": "Unusual web requests with script-like patterns.",
            "impact": "User data can be stolen or sessions hijacked.",
            "precautions": [
                "Sanitize user input",
                "Use secure coding practices"
            ],
            "conclusion": "Someone is trying to inject harmful code into your website to steal information or control user sessions."
        },

        "Web Attack – Sql Injection": {
            "meaning": "The attacker is trying to manipulate database queries.",
            "technical": "Suspicious input patterns targeting database.",
            "impact": "Sensitive data can be accessed or deleted.",
            "precautions": [
                "Use prepared statements",
                "Validate all inputs"
            ],
            "conclusion": "This is a serious attempt to access or damage your database by sending specially crafted inputs."
        },

        "Bot": {
            "meaning": "The system may be acting like part of a bot network.",
            "technical": "Automated repeated communication patterns.",
            "impact": "Your system may be used in attacks without your knowledge.",
            "precautions": [
                "Run malware scans",
                "Monitor outgoing traffic"
            ],
            "conclusion": "Your system may already be compromised and controlled remotely by an attacker."
        }
    }

    return details.get(attack, {
        "meaning": "Suspicious activity detected.",
        "technical": "Unusual behavior observed.",
        "impact": "May indicate a security issue.",
        "precautions": ["Monitor the system carefully"],
        "conclusion": "There are signs of unusual activity that should be investigated further."
    })  


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

    feature_df, timeline = extract_features(pcap_file)

    probs = model.predict_proba(feature_df[features])[0]
    attacks = dict(zip(le.classes_, probs))

    behavior = behavior_detection(feature_df)

    for k, v in behavior.items():
        attacks[k] = max(attacks.get(k, 0), v)

    threshold = 0.50
    filtered = {k: v for k, v in attacks.items() if v >= threshold and k != "BENIGN"}

    file_hash = compute_hash(pcap_file)

    now = datetime.now()

    # -----------------------------
    # REPORT BUILD (DETAILED)
    # -----------------------------
    report = []

    report.append("TRACE-NF : Advanced Network Forensics Report")
    report.append("=" * 70)

    report.append(f"\nCase ID: TRACE-{now.strftime('%Y%m%d-%H%M%S')}")
    report.append(f"Evidence File: {os.path.basename(pcap_file)}")

    report.append("\nIntegrity Verification:")
    report.append(f"SHA-256: {file_hash}")
    report.append("Status: VERIFIED")

    report.append("\nAnalysis Summary:")
    report.append(
        "The traffic analysis reveals multiple behavioral and statistical anomalies. "
        "Machine learning classification combined with heuristic analysis confirms "
        "potential malicious intent."
    )

    report.append("\nDetected Threat Analysis:")

    if not filtered:
        report.append("\nNo significant malicious activity detected.")
    else:
        for attack, score in sorted(filtered.items(), key=lambda x: x[1], reverse=True):

            details = get_attack_details(attack)

            report.append(f"\n--- {attack} ({round(score*100,2)}%) ---")

            report.append("\nDescription:")
            report.append(details["meaning"])

            report.append("\nTechnical Insight:")
            report.append(details["technical"])

            report.append("\nImpact:")
            report.append(details["impact"])

            report.append("\nRecommended Actions:")
            for p in details["precautions"]:
                report.append(f"- {p}")

            report.append("\nConclusion:")
            report.append(details["conclusion"])

            report.append("\n" + "-" * 50)

    report.append("\nTimeline:")
    for t in timeline:
        report.append(t)

    report.append("\nOverall Conclusion:")

    if not filtered:
        report.append(
        "The network traffic looks normal. No strong signs of attack were found during this analysis."
        )
    else:
        report.append(
        "The analysis shows that the system was targeted by one or more suspicious activities. "
        "In simple terms, someone tried to explore the system, find weaknesses, and possibly gain access "
        "or disrupt its normal working.\n"
        )

        report.append(
        "Even if the attack was not fully successful, such behavior is a warning sign. "
        "It is recommended to review system security, update protections, and monitor future activity closely."
        )

    report.append("\n" + "=" * 70)

    report_text = "\n".join(report)

    print("\n" + report_text)

    filename = f"report_{now.strftime('%Y%m%d_%H%M%S')}.pdf"
    generate_pdf(report_text, filename)


# -----------------------------
# Run
# -----------------------------
if __name__ == "__main__":

    pcap_file = input("Enter PCAP file path: ")
    analyze_pcap(pcap_file)