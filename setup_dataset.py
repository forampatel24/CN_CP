import os
import subprocess
import pandas as pd
import numpy as np

# -----------------------------
# CONFIG
# -----------------------------
DATASET = "chethuhn/network-intrusion-dataset"
DATA_FOLDER = "data"
OUTPUT_FILE = "data/combined.csv"

KAGGLE_PATH = r"C:\Users\Dell'\AppData\Roaming\Python\Python312\Scripts\kaggle.exe"


# -----------------------------
# DOWNLOAD DATASET
# -----------------------------
def download_dataset():
    print("Downloading CICIDS2017 dataset...")

    os.makedirs(DATA_FOLDER, exist_ok=True)

    subprocess.run([
        KAGGLE_PATH,
        "datasets", "download",
        "-d", DATASET,
        "-p", DATA_FOLDER,
        "--unzip"
    ], check=True)

    print("Download complete!")


# -----------------------------
# LOAD AND MERGE CSV FILES
# -----------------------------
def merge_csv_files():
    print("Merging CSV files...")

    csv_files = [
        os.path.join(DATA_FOLDER, f)
        for f in os.listdir(DATA_FOLDER)
        if f.endswith(".csv")
    ]

    df_list = []

    for file in csv_files:
        print("Loading:", file)
        df = pd.read_csv(file, low_memory=False)
        df_list.append(df)

    df = pd.concat(df_list, ignore_index=True)

    print("Total rows:", len(df))

    return df


# -----------------------------
# PREPROCESS DATA
# -----------------------------
def preprocess(df):

    print("Cleaning dataset...")

    # Remove spaces in column names
    df.columns = df.columns.str.strip()

    # Replace infinite values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Drop NaN rows
    df.dropna(inplace=True)

    print("Rows after cleaning:", len(df))

    # Fix label column
    if "Label" not in df.columns:
        raise Exception("Label column not found!")

    # Standardize labels
    df["Label"] = df["Label"].str.strip()

    print("Attack types found:")
    print(df["Label"].value_counts())

    return df


# -----------------------------
# SAVE DATASET
# -----------------------------
def save_dataset(df):

    print("Saving processed dataset...")

    df.to_csv(OUTPUT_FILE, index=False)

    print("Dataset saved at:", OUTPUT_FILE)


# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":

    download_dataset()

    df = merge_csv_files()

    df = preprocess(df)

    save_dataset(df)

    print("Dataset ready for model training!")