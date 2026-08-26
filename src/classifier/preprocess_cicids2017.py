"""
CICIDS2017 preprocessing pipeline.

Handles the dataset issues flagged by Dr. Pavlović:
  - whitespace in column names
  - infinite values (Flow Bytes/s, Flow Packets/s division-by-zero artifacts)
  - missing values
  - severe class imbalance
  - robust scaling (dataset has heavy outliers, so RobustScaler > StandardScaler)

Usage:
    python preprocess_cicids2017.py --input-dir ./raw_csvs --output-dir ./processed
"""

import argparse
import glob
import json
import os

import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler, LabelEncoder

LABEL_COL = "Label"


def load_and_merge_csvs(input_dir: str) -> pd.DataFrame:
    """Load all CICIDS2017 CSVs in a directory and concatenate them."""
    csv_paths = sorted(glob.glob(os.path.join(input_dir, "*.csv")))
    if not csv_paths:
        raise FileNotFoundError(f"No CSV files found in {input_dir}")

    frames = []
    for path in csv_paths:
        df = pd.read_csv(path, low_memory=False, encoding="latin1")
        df.columns = df.columns.str.strip()  # fixes the leading-whitespace quirk
        frames.append(df)
        print(f"  loaded {os.path.basename(path)}: {df.shape[0]} rows")

    merged = pd.concat(frames, ignore_index=True)
    print(f"Merged shape: {merged.shape}")
    return merged


def drop_degenerate_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Drop constant columns — they add noise, not signal, for a classifier."""
    nunique = df.nunique(dropna=False)
    constant_cols = nunique[nunique <= 1].index.tolist()
    if constant_cols:
        print(f"Dropping {len(constant_cols)} constant columns: {constant_cols}")
        df = df.drop(columns=constant_cols)
    return df


def handle_infinities_and_missing(df: pd.DataFrame) -> pd.DataFrame:
    """CICIDS2017's Flow Bytes/s and Flow Packets/s contain inf values where
    flow duration was 0 (division by zero in the original CICFlowMeter export).
    We replace inf with NaN, then impute with the column median (robust to
    the heavy skew in flow-based features — mean would be pulled by outliers).
    """
    numeric_cols = df.select_dtypes(include=[np.number]).columns

    n_inf = np.isinf(df[numeric_cols]).sum().sum()
    print(f"Replacing {n_inf} infinite values with NaN")
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)

    n_missing_before = df[numeric_cols].isna().sum().sum()
    medians = df[numeric_cols].median()
    df[numeric_cols] = df[numeric_cols].fillna(medians)
    print(f"Imputed {n_missing_before} missing/inf values with column medians")

    # Any remaining non-numeric missing values (rare, but be defensive)
    df = df.dropna()
    return df


def clean_labels(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize label strings — CICIDS2017 has inconsistent spacing/casing
    across files (e.g. 'Web Attack \x96 Brute Force' vs clean variants)."""
    df[LABEL_COL] = df[LABEL_COL].astype(str).str.strip()
    print("Class distribution before any resampling:")
    print(df[LABEL_COL].value_counts())
    return df


def encode_and_scale(df: pd.DataFrame):
    """Encode labels, scale features with RobustScaler (median/IQR-based —
    appropriate here because flow features have extreme outliers that would
    distort a standard z-score scaler)."""
    y_raw = df[LABEL_COL]
    X = df.drop(columns=[LABEL_COL])

    # Keep only numeric feature columns for the model
    X = X.select_dtypes(include=[np.number])

    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(y_raw)

    scaler = RobustScaler()
    X_scaled = pd.DataFrame(scaler.fit_transform(X), columns=X.columns, index=X.index)

    return X_scaled, y, label_encoder, scaler


def compute_class_weights(y: np.ndarray, label_encoder: LabelEncoder) -> dict:
    """Return class weights (inverse frequency) for use in XGBoost's
    sample_weight or scale_pos_weight — this is the recommended first line
    of defense against class imbalance before reaching for synthetic
    resampling (SMOTE), which can introduce unrealistic flow-feature
    combinations for minority attack classes."""
    counts = pd.Series(y).value_counts()
    total = len(y)
    n_classes = len(counts)
    weights = {cls: total / (n_classes * count) for cls, count in counts.items()}

    named_weights = {
        label_encoder.inverse_transform([cls])[0]: round(w, 3)
        for cls, w in weights.items()
    }
    print("Computed class weights (inverse frequency):")
    print(json.dumps(named_weights, indent=2))
    return weights


def main():
    parser = argparse.ArgumentParser(description="Preprocess CICIDS2017 dataset")
    parser.add_argument("--input-dir", required=True, help="Directory of raw CICIDS2017 CSVs")
    parser.add_argument("--output-dir", required=True, help="Where to write processed files")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    print("== Loading and merging CSVs ==")
    df = load_and_merge_csvs(args.input_dir)

    print("\n== Dropping degenerate columns ==")
    df = drop_degenerate_columns(df)

    print("\n== Handling infinite/missing values ==")
    df = handle_infinities_and_missing(df)

    print("\n== Cleaning labels ==")
    df = clean_labels(df)

    print("\n== Encoding and scaling ==")
    X, y, label_encoder, scaler = encode_and_scale(df)

    print("\n== Computing class weights ==")
    class_weights = compute_class_weights(y, label_encoder)

    # Persist outputs
    X.to_parquet(os.path.join(args.output_dir, "X_features.parquet"))
    np.save(os.path.join(args.output_dir, "y_labels.npy"), y)

    with open(os.path.join(args.output_dir, "label_classes.json"), "w") as f:
        json.dump(list(label_encoder.classes_), f, indent=2)

    with open(os.path.join(args.output_dir, "class_weights.json"), "w") as f:
        json.dump({str(k): v for k, v in class_weights.items()}, f, indent=2)

    print(f"\nDone. Processed data written to {args.output_dir}")
    print(f"Final feature matrix: {X.shape}, labels: {y.shape}")


if __name__ == "__main__":
    main()