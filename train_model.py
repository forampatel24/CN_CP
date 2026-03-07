import numpy as np
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import os

DATASET_PATH = "data/combine.csv"
MODEL_PATH = "model/attack_model.pkl"

def load_dataset():

    df = pd.read_csv(DATASET_PATH, low_memory=False)

    # remove leading spaces
    df.columns = df.columns.str.strip()

    # Strong feature set for attack detection
    features = [

        "Destination Port",
        "Flow Duration",

        "Total Fwd Packets",
        "Total Backward Packets",

        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",

        "Flow Bytes/s",
        "Flow Packets/s",

        "Packet Length Mean",
        "Packet Length Std",

        "Fwd Packet Length Mean",
        "Bwd Packet Length Mean",

        "FIN Flag Count",
        "SYN Flag Count",
        "RST Flag Count",
        "PSH Flag Count",
        "ACK Flag Count",

        "Average Packet Size",

        "Active Mean",
        "Idle Mean"
    ]

    # Detect label column
    if "Label" in df.columns:
        label_col = "Label"
    else:
        raise Exception("Label column not found")

    df = df[features + [label_col]]

    # Convert to numeric
    for col in features:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Remove bad values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    # Map CICIDS labels to your categories
    def map_attack(label):

        label = str(label).lower()

        if "benign" in label:
            return "Normal Traffic"

        elif "portscan" in label:
            return "Port Scan"

        elif "brute" in label or "patator" in label:
            return "Brute Force"

        elif "dos" in label or "ddos" in label:
            return "Flooding"

        elif "bot" in label:
            return "Persistence"

        else:
            return "Normal Traffic"

    df["Attack"] = df[label_col].apply(map_attack)

    X = df[features]
    y = df["Attack"]

    return X, y, features


def train_model():

    X, y, features = load_dataset()

    le = LabelEncoder()
    y_encoded = le.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42
    )

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_train, y_train)

    os.makedirs("model", exist_ok=True)

    joblib.dump({
        "model": model,
        "label_encoder": le,
        "features": features
    }, MODEL_PATH)

    print("Model trained and saved to", MODEL_PATH)


if __name__ == "__main__":
    train_model()