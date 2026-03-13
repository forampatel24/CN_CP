import pandas as pd
import numpy as np

df = pd.read_csv("data/combined.csv", low_memory=False)

print("Dataset Shape:")
print(df.shape)

print("\nColumns:")
print(len(df.columns))

print("\nUnique Labels:")
print(df["Label"].unique())

print("\nLabel Distribution:")
print(df["Label"].value_counts())

print("\nMissing Values:")
print(df.isna().sum().sum())

numeric_cols = df.select_dtypes(include=np.number).columns

print("\nInfinite values:")
print(np.isinf(df[numeric_cols]).sum().sum())

print("\nSample Data:")
print(df.head())