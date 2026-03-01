import os
import subprocess
import sys

DATA_PATH = "data/cicids2017_cleaned.csv"

def download_dataset():
    print("Downloading CICIDS2017 dataset from Kaggle...")

    os.makedirs("data", exist_ok=True)

    try:
        subprocess.run([
            "kaggle", "datasets", "download",
            "-d", "ericanacletoribeiro/cicids2017-cleaned-and-preprocessed",
            "-p", "data",
            "--unzip"
        ], check=True)

        print("Dataset downloaded successfully!")

    except subprocess.CalledProcessError:
        print("Error: Kaggle CLI not configured.")
        print("Please install Kaggle and add kaggle.json API key.")
        sys.exit(1)


if not os.path.exists(DATA_PATH):
    download_dataset()
else:
    print("Dataset already exists. Skipping download.")