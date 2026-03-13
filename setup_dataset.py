import os
import subprocess
import pandas as pd
import numpy as np

DATASET = "chethuhn/network-intrusion-dataset"
DATA_FOLDER = "data"
OUTPUT_FILE = "data/combined.csv"

KAGGLE_PATH = r"C:\Users\Dell'\AppData\Roaming\Python\Python312\Scripts\kaggle.exe"


# -----------------------------
# Download dataset
# -----------------------------
def download_dataset():

    os.makedirs(DATA_FOLDER, exist_ok=True)

    subprocess.run([
        KAGGLE_PATH,
        "datasets",
        "download",
        "-d",
        DATASET,
        "-p",
        DATA_FOLDER,
        "--unzip"
    ], check=True)


# -----------------------------
# Load dataset files
# -----------------------------
def load_and_concat():

    # Loading the dataset
    data1 = pd.read_csv(f"{DATA_FOLDER}/Monday-WorkingHours.pcap_ISCX.csv", low_memory=False)
    data2 = pd.read_csv(f"{DATA_FOLDER}/Tuesday-WorkingHours.pcap_ISCX.csv", low_memory=False)
    data3 = pd.read_csv(f"{DATA_FOLDER}/Wednesday-workingHours.pcap_ISCX.csv", low_memory=False)
    data4 = pd.read_csv(f"{DATA_FOLDER}/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv", low_memory=False)
    data5 = pd.read_csv(f"{DATA_FOLDER}/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv", low_memory=False)
    data6 = pd.read_csv(f"{DATA_FOLDER}/Friday-WorkingHours-Morning.pcap_ISCX.csv", low_memory=False)
    data7 = pd.read_csv(f"{DATA_FOLDER}/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", low_memory=False)
    data8 = pd.read_csv(f"{DATA_FOLDER}/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", low_memory=False)

    data_list = [data1, data2, data3, data4, data5, data6, data7, data8]

    print('Data dimensions: ')
    for i, data in enumerate(data_list, start=1):
        rows, cols = data.shape
        print(f'Data{i} -> {rows} rows, {cols} columns')

    data = pd.concat(data_list)

    rows, cols = data.shape

    print('New dimension:')
    print(f'Number of rows: {rows}')
    print(f'Number of columns: {cols}')
    print(f'Total cells: {rows * cols}')

    # delete individual dfs
    for d in data_list:
        del d

    return data


# -----------------------------
# Cleaning dataset
# -----------------------------
def clean_dataset(data):

    # Renaming the columns by removing whitespace
    col_names = {col: col.strip() for col in data.columns}
    data.rename(columns=col_names, inplace=True)

    pd.options.display.max_rows = 80

    print('Overview of Columns:')
    print(data.describe().transpose())

    # duplicates
    dups = data[data.duplicated()]
    print(f'Number of duplicates: {len(dups)}')

    data.drop_duplicates(inplace=True)

    print("Shape after removing duplicates:", data.shape)

    # missing values
    missing_val = data.isna().sum()
    print(missing_val.loc[missing_val > 0])

    # infinity values
    numeric_cols = data.select_dtypes(include=np.number).columns
    inf_count = np.isinf(data[numeric_cols]).sum()

    print(inf_count[inf_count > 0])

    # replace infinite values
    print(f'Initial missing values: {data.isna().sum().sum()}')

    data.replace([np.inf, -np.inf], np.nan, inplace=True)

    print(f'Missing values after processing infinite values: {data.isna().sum().sum()}')

    missing = data.isna().sum()

    print(missing.loc[missing > 0])

    # missing percentage
    mis_per = (missing / len(data)) * 100

    mis_table = pd.concat([missing, mis_per.round(2)], axis=1)

    mis_table = mis_table.rename(columns={
        0: 'Missing Values',
        1: 'Percentage of Total Values'
    })

    print(mis_table.loc[mis_per > 0])

    # -----------------------------
    # REMOVE NaN rows
    # -----------------------------
    data.dropna(inplace=True)

    print("\nShape after removing NaN rows:", data.shape)

    return data


# -----------------------------
# Save dataset
# -----------------------------
def save_dataset(data):

    data.to_csv(OUTPUT_FILE, index=False)

    print(f"\nDataset saved to {OUTPUT_FILE}")


# -----------------------------
# MAIN
# -----------------------------
if __name__ == "__main__":

    download_dataset()

    data = load_and_concat()

    data = clean_dataset(data)

    save_dataset(data)