import numpy as np
import pandas as pd
import joblib
import os

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report


DATASET_PATH = "data/combined.csv"
MODEL_PATH = "model/attack_model.pkl"


FEATURES = [

"Destination Port",
"Flow Duration",
"Total Fwd Packets",
"Total Length of Fwd Packets",

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

"Fwd Header Length",
"Bwd Header Length",

"Fwd Packets/s",
"Bwd Packets/s",

"Min Packet Length",
"Max Packet Length",
"Packet Length Mean",
"Packet Length Std",
"Packet Length Variance",

"FIN Flag Count",
"PSH Flag Count",
"ACK Flag Count",

"Average Packet Size",

"Subflow Fwd Bytes",

"Init_Win_bytes_forward",
"Init_Win_bytes_backward",

"act_data_pkt_fwd",
"min_seg_size_forward",

"Active Mean",
"Active Max",
"Active Min",

"Idle Mean",
"Idle Max",
"Idle Min"

]


# attacks to ignore
REMOVE_ATTACKS = [
    "Heartbleed",
    "Web Attack � Sql Injection",
    "Infiltration"
]


def load_dataset():

    print("Loading dataset...")

    df = pd.read_csv(DATASET_PATH, low_memory=False)

    df.columns = df.columns.str.strip()

    # remove rare attacks
    df = df[~df["Label"].isin(REMOVE_ATTACKS)]

    print("\nRemaining attacks:")
    print(df["Label"].value_counts())

    # keep only required features
    df = df[FEATURES + ["Label"]]

    # convert to numeric
    for col in FEATURES:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)

    # OPTIONAL: sample dataset for faster training
    SAMPLE_SIZE = 500000

    if len(df) > SAMPLE_SIZE:
        print("\nSampling dataset for faster training...")
        df = df.sample(SAMPLE_SIZE, random_state=42)

    X = df[FEATURES]
    y = df["Label"]

    return X, y


def train_model():

    X, y = load_dataset()

    le = LabelEncoder()

    y_encoded = le.fit_transform(y)

    print("\nClasses detected:")
    print(le.classes_)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y_encoded,
        test_size=0.2,
        stratify=y_encoded,
        random_state=42
    )

    model = RandomForestClassifier(
        n_estimators=400,
        max_depth=None,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    print("\nTraining Random Forest...")

    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    print("\nClassification Report:\n")

    print(classification_report(
        y_test,
        y_pred,
        target_names=le.classes_
    ))

    os.makedirs("model", exist_ok=True)

    joblib.dump(
        {
            "model": model,
            "label_encoder": le,
            "features": FEATURES
        },
        MODEL_PATH
    )

    print("\nModel saved to:", MODEL_PATH)


if __name__ == "__main__":
    train_model()