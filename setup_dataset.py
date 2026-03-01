import os
import subprocess

DATASET = "ericanacletoribeiro/cicids2017-cleaned-and-preprocessed"
DATA_FOLDER = "data"

KAGGLE_PATH = r"C:\Users\Dell'\AppData\Roaming\Python\Python312\Scripts\kaggle.exe"

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

if __name__ == "__main__":
    download_dataset()