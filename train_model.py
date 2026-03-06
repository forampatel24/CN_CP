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

    # Remove spaces in column names
    df.columns = df.columns.str.strip()

    features = [
        'Destination Port',
        'Flow Duration',
        'Total Fwd Packets',
        'Total Backward Packets',
        'Flow Bytes/s',
        'Flow Packets/s'
    ]

    # detect label column automatically
    if 'Label' in df.columns:
        label_col = 'Label'
    elif 'Attack Type' in df.columns:
        label_col = 'Attack Type'
    else:
        raise Exception("No label column found")

    df = df[features + [label_col]]

    # convert feature columns to numeric
    # convert feature columns to numeric
    for col in features:
        df[col] = pd.to_numeric(df[col], errors='coerce')

# remove infinity values (caused by divide by zero in dataset)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

# remove corrupted rows
    df = df.dropna()

    def map_attack(label):
        label = str(label).lower()

        if "benign" in label:
            return "Normal Traffic"
        elif "portscan" in label:
            return "Port Scan"
        elif "brute" in label:
            return "Brute Force"
        elif "dos" in label or "ddos" in label:
            return "Flooding"
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

    model = RandomForestClassifier(n_estimators=100)
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