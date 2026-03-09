import numpy as np
import pandas as pd
import joblib
import os

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report


DATASET_PATH = "data/combine.csv"
MODEL_PATH = "model/attack_model.pkl"


def load_dataset():

    print("Loading dataset...")

    df = pd.read_csv(DATASET_PATH, low_memory=False)

    # remove leading spaces in column names
    df.columns = df.columns.str.strip()

    # Strong CICIDS feature set
    features = [

        "Destination Port",
        "Flow Duration",

        "Total Fwd Packets",
        "Total Backward Packets",

        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",

        "Fwd Packet Length Max",
        "Fwd Packet Length Min",
        "Fwd Packet Length Mean",
        "Fwd Packet Length Std",

        "Bwd Packet Length Max",
        "Bwd Packet Length Min",
        "Bwd Packet Length Mean",
        "Bwd Packet Length Std",

        "Flow Bytes/s",
        "Flow Packets/s",

        "Flow IAT Mean",
        "Flow IAT Std",
        "Flow IAT Max",
        "Flow IAT Min",

        "Fwd IAT Total",
        "Fwd IAT Mean",
        "Fwd IAT Std",
        "Fwd IAT Max",
        "Fwd IAT Min",

        "Bwd IAT Total",
        "Bwd IAT Mean",
        "Bwd IAT Std",
        "Bwd IAT Max",
        "Bwd IAT Min",

        "Fwd Packets/s",
        "Bwd Packets/s",

        "Packet Length Mean",
        "Packet Length Std",
        "Packet Length Variance",

        "FIN Flag Count",
        "SYN Flag Count",
        "RST Flag Count",
        "PSH Flag Count",
        "ACK Flag Count",

        "Average Packet Size",

        "Active Mean",
        "Active Max",
        "Active Min",

        "Idle Mean",
        "Idle Max",
        "Idle Min"
    ]

    label_col = "Label"

    print("Selecting features...")

    df = df[features + [label_col]]

    # Convert columns to numeric
    for col in features:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Remove bad values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    print("Mapping attack labels...")

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

    print("Dataset ready.")
    print("Samples:", len(df))

    return X, y, features


def train_model():

    X, y, features = load_dataset()

    print("Encoding labels...")

    le = LabelEncoder()
    y_encoded = le.fit_transform(y)

    print("Splitting dataset...")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y_encoded,
        test_size=0.2,
        stratify=y_encoded,
        random_state=42
    )

    print("Training RandomForest model...")

    model = RandomForestClassifier(
        n_estimators=400,
        max_depth=25,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_train, y_train)

    print("\nEvaluating model...\n")

    y_pred = model.predict(X_test)

    print(classification_report(
        y_test,
        y_pred,
        target_names=le.classes_
    ))

    # Feature importance
    importance = pd.Series(
        model.feature_importances_,
        index=features
    ).sort_values(ascending=False)

    print("\nTop Important Features:\n")
    print(importance.head(15))

    print("\nSaving model...")

    os.makedirs("model", exist_ok=True)

    joblib.dump(
        {
            "model": model,
            "label_encoder": le,
            "features": features
        },
        MODEL_PATH
    )

    print("\nModel successfully saved to:", MODEL_PATH)


if __name__ == "__main__":
    train_model()