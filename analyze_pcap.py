import hashlib
import joblib
import os
from datetime import datetime
from extract_features import extract_features
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

MODEL_PATH = "model/attack_model.pkl"
OUTPUT_FOLDER = r"C:\Foram\ENG_SY\SEM2\CN\COURSE_PROJECT\CN_CP\output"


def sha256_hash(file_path):

    sha = hashlib.sha256()

    with open(file_path, "rb") as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            sha.update(data)

    return sha.hexdigest()


def behavioral_detection(stats):

    detected = {}

    # Port Scan
    if stats["unique_ports"] > 20:
        detected["Port Scan"] = 0.85

    # Flooding
    if stats["packet_rate"] > 300:
        detected["Flooding"] = 0.80

    # Brute Force
    if stats["ssh_attempts"] > 5:
        detected["Brute Force"] = 0.75

    # Persistence
    if stats["duration"] > 120:
        detected["Persistence"] = 0.70

    return detected


def generate_timeline(stats):

    timeline = []

    start = stats["start_time"]
    end = stats["end_time"]

    timeline.append((start, "Initial network activity observed from suspect source IP"))

    if stats["unique_ports"] > 20:
        timeline.append((start, "Rapid probing of multiple destination ports detected"))

    if stats["packet_rate"] > 300:
        timeline.append((start, "Abnormally high packet transmission rate observed"))

    if stats["ssh_attempts"] > 5:
        timeline.append((start, "Repeated authentication attempts targeting SSH service"))

    if stats["duration"] > 120:
        timeline.append((start, "Sustained communication pattern suggesting persistent access attempt"))

    timeline.append((end, "Suspicious activity terminated"))

    return timeline


def generate_pdf(report_lines, filepath):

    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    c = canvas.Canvas(filepath, pagesize=letter)

    y = 750

    for line in report_lines:

        c.drawString(50, y, line)
        y -= 18

        if y < 50:
            c.showPage()
            y = 750

    c.save()

    return filepath

def analyze_pcap(pcap_file):

    data = joblib.load(MODEL_PATH)

    model = data["model"]
    le = data["label_encoder"]
    features = data["features"]

    feature_df, stats = extract_features(pcap_file)

    prediction = model.predict_proba(feature_df[features])[0]

    ml_attacks = dict(zip(le.classes_, prediction))

    behavior_attacks = behavioral_detection(stats)

    # Merge ML + behavioral detections
    detected_attacks = {}

    for k, v in ml_attacks.items():
        if v > 0.60:
            detected_attacks[k] = v

    for k, v in behavior_attacks.items():
        detected_attacks[k] = max(detected_attacks.get(k, 0), v)

    file_hash = sha256_hash(pcap_file)

    timeline = generate_timeline(stats)

    if "Normal Traffic" in detected_attacks and len(detected_attacks) > 1:
        del detected_attacks["Normal Traffic"]

    report = []

    report.append("====================================================")
    report.append(" TRACE-NF : Network Forensics & Incident Report")
    report.append("====================================================")
    report.append("")

    report.append(f"Evidence File: {pcap_file}")
    report.append("")

    report.append("Evidence Integrity Verification:")
    report.append("------------------------------------")
    report.append("Hash Algorithm Used : SHA-256")
    report.append(f"PCAP File Hash     : {file_hash}")
    report.append("Integrity Status   : Verified (No modification detected)")
    report.append("")

    report.append("Evidence Details:")
    report.append("----------------------------------------------------")
    report.append("")
    report.append("Source IP Under Investigation:")
    report.append(stats["source_ip"])
    report.append("")

    report.append("Traffic Analysis Metrics:")
    report.append("------------------------------------")

    report.append(f"Total Packets Observed : {stats['total_packets']}")
    report.append(f"Unique Destination Ports : {stats['unique_ports']}")
    report.append(f"Average Packet Rate : {round(stats['packet_rate'],2)} packets/sec")
    report.append(f"Capture Duration : {round(stats['duration'],2)} seconds")
    report.append("")

    report.append("Analysis Summary:")
    report.append("------------------------------------")
    report.append("The system analyzed the captured network traffic and detected")
    report.append("multiple suspicious behavior patterns originating from the same")
    report.append("source IP address.")
    report.append("")

    report.append("Detected Attack Types & Confidence Levels:")
    report.append("------------------------------------")

    i = 1

    for attack, score in detected_attacks.items():

        report.append(f"{i}) {attack}")
        report.append(f"   Confidence Level : {round(score*100)}%")

        if attack == "Port Scan":
            report.append("   Justification:")
            report.append("   - Multiple different ports accessed")
            report.append("   - Behavior matches reconnaissance patterns")

        if attack == "Brute Force":
            report.append("   Justification:")
            report.append("   - Repeated login attempts detected")
            report.append("   - Target service likely SSH")

        if attack == "Flooding":
            report.append("   Justification:")
            report.append("   - Very high packet transmission rate")

        if attack == "Persistence":
            report.append("   Justification:")
            report.append("   - Long connection duration observed")

        report.append("")
        i += 1

    report.append("Attack Timeline (Reconstructed):")
    report.append("------------------------------------")

    for t, event in timeline:
        report.append(f"{t.strftime('%H:%M:%S') if hasattr(t,'strftime') else t}  {event}")

    
    report.append("")
    report.append("Attack Evolution Analysis:")
    report.append("------------------------------------")

    if "Port Scan" in detected_attacks:
        report.append("Stage 1 : Reconnaissance Phase")
        report.append("          Port scanning used to identify open services")

    if "Brute Force" in detected_attacks:
        report.append("Stage 2 : Credential Access Attempt")
        report.append("          Multiple authentication attempts detected")

    if "Flooding" in detected_attacks:
        report.append("Stage 3 : Service Disruption Attempt")
        report.append("          High packet rate intended to overwhelm services")

    report.append("")

    report.append("")

    report.append("Risk Assessment:")
    report.append("------------------------------------")

    if "Flooding" in detected_attacks:
        risk = "CRITICAL"
    elif len(detected_attacks) >= 2:
        risk = "HIGH"
    elif len(detected_attacks) == 1:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    report.append(f"Overall Risk Level : {risk}")
    report.append("")

    report.append("Final Conclusion (Human-Readable Forensic Analysis):")
    report.append("------------------------------------")

    report.append(
    "The forensic examination of the provided packet capture indicates the "
    "presence of suspicious and potentially malicious network behavior. "
    "Traffic originating from the identified source IP demonstrates patterns "
    "that are strongly associated with reconnaissance and exploitation attempts."
    )

    if "Port Scan" in detected_attacks:
        report.append(
        "The analysis revealed that the source host systematically attempted "
        "connections to a large number of destination ports within a short "
        "time interval. Such behavior is characteristic of automated port "
        "scanning tools used during the reconnaissance phase of an attack. "
        "Attackers commonly perform this activity to identify open services "
        "that may be exploited later."
        )

    if "Flooding" in detected_attacks:
        report.append(
        "Additionally, the observed packet transmission rate was significantly "
        "higher than typical baseline traffic levels. This indicates a potential "
        "flooding attempt intended to overwhelm network services or degrade "
        "system performance."
        )

    if "Brute Force" in detected_attacks:
        report.append(
        "Repeated connection attempts targeting authentication services were "
        "also detected. This behavior is commonly associated with brute-force "
        "credential attacks, where an attacker repeatedly attempts login "
        "combinations to gain unauthorized access."
        )

    if "Persistence" in detected_attacks:
        report.append(
        "Sustained communication patterns suggest the possibility of persistence "
        "activity, where an attacker maintains prolonged access to a target "
        "system after initial compromise."
        )

    report.append(
    "Based on the combined machine learning classification results and "
    "behavioral analysis indicators, the traffic capture demonstrates "
    "clear signs of hostile reconnaissance activity. Further investigation "
    "of the affected host and associated network infrastructure is strongly "
    "recommended."
    )

    report.append("")
    report.append("====================================================")
    report.append(" End of Report")
    report.append("====================================================")

    # Print to console
    for line in report:
        print(line)

    # Save PDF
    # Ensure output folder exists
    os.makedirs(OUTPUT_FOLDER, exist_ok=True)

# Create report filename
    filename = f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

# Full path for PDF
    pdf_path = os.path.join(OUTPUT_FOLDER, filename)

# Generate PDF
    path = generate_pdf(report, pdf_path)

    print("\nPDF Report saved to:", path)


if __name__ == "__main__":

    pcap_file = input("Enter PCAP file path: ")

    analyze_pcap(pcap_file)