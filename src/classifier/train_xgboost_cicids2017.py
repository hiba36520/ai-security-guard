"""
Entrainement XGBoost sur les features CICIDS2017 pre-traitees.

Usage:
    python train_xgboost_cicids2017.py --data-dir ./processed --output-dir ./model_artifacts
"""

import argparse
import json
import os

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, f1_score
import matplotlib.pyplot as plt


def load_processed_data(data_dir: str):
    X = pd.read_parquet(os.path.join(data_dir, "X_features.parquet"))
    y = np.load(os.path.join(data_dir, "y_labels.npy"))

    with open(os.path.join(data_dir, "label_classes.json")) as f:
        label_classes = json.load(f)

    with open(os.path.join(data_dir, "class_weights.json")) as f:
        class_weights = {int(k): v for k, v in json.load(f).items()}

    return X, y, label_classes, class_weights


def build_sample_weights(y: np.ndarray, class_weights: dict) -> np.ndarray:
    return np.array([class_weights[label] for label in y])


def train_model(X_train, y_train, sample_weight_train, n_classes: int, n_estimators: int, max_depth: int):
    model = xgb.XGBClassifier(
        objective="multi:softprob",
        num_class=n_classes,
        n_estimators=n_estimators,
        max_depth=max_depth,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric="mlogloss",
        tree_method="hist",
        n_jobs=-1,
        random_state=42,
    )
    model.fit(X_train, y_train, sample_weight=sample_weight_train)
    return model


def evaluate_model(model, X_test, y_test, label_classes, output_dir: str):
    y_pred = model.predict(X_test)

    report = classification_report(
        y_test, y_pred, target_names=label_classes, output_dict=True, zero_division=0
    )
    print(classification_report(y_test, y_pred, target_names=label_classes, zero_division=0))

    macro_f1 = f1_score(y_test, y_pred, average="macro")
    print(f"Macro F1: {macro_f1:.4f}")

    with open(os.path.join(output_dir, "classification_report.json"), "w") as f:
        json.dump(report, f, indent=2)

    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(12, 10))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks(range(len(label_classes)))
    ax.set_yticks(range(len(label_classes)))
    ax.set_xticklabels(label_classes, rotation=90)
    ax.set_yticklabels(label_classes)
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title("CICIDS2017 Confusion Matrix")
    fig.colorbar(im)
    fig.tight_layout()
    fig.savefig(os.path.join(output_dir, "confusion_matrix.png"), dpi=150)
    print(f"Confusion matrix saved to {output_dir}/confusion_matrix.png")

    return macro_f1


def run_shap_analysis(model, X_test, output_dir: str, sample_size: int = 2000):
    import shap

    sample = X_test.sample(n=min(sample_size, len(X_test)), random_state=42)
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(sample)

    plt.figure()
    shap.summary_plot(shap_values, sample, show=False, max_display=15)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "shap_summary.png"), dpi=150, bbox_inches="tight")
    print(f"SHAP summary saved to {output_dir}/shap_summary.png")


def main():
    parser = argparse.ArgumentParser(description="Train XGBoost on CICIDS2017")
    parser.add_argument("--data-dir", required=True, help="Output dir from preprocess_cicids2017.py")
    parser.add_argument("--output-dir", required=True, help="Where to save model + evaluation artifacts")
    parser.add_argument("--skip-shap", action="store_true", help="Skip SHAP analysis (slower step)")
    parser.add_argument("--n-estimators", type=int, default=400, help="Number of trees")
    parser.add_argument("--max-depth", type=int, default=8, help="Tree depth")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    print("== Loading processed data ==")
    X, y, label_classes, class_weights = load_processed_data(args.data_dir)
    print(f"Features: {X.shape}, classes: {len(label_classes)}")

    print("\n== Splitting train/test (stratified) ==")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )
    print(f"Train: {X_train.shape}, Test: {X_test.shape}")

    sample_weight_train = build_sample_weights(y_train, class_weights)

    print("\n== Training XGBoost ==")
    model = train_model(X_train, y_train, sample_weight_train, n_classes=len(label_classes),
                         n_estimators=args.n_estimators, max_depth=args.max_depth)

    print("\n== Evaluating ==")
    macro_f1 = evaluate_model(model, X_test, y_test, label_classes, args.output_dir)

    if not args.skip_shap:
        print("\n== SHAP analysis ==")
        run_shap_analysis(model, X_test, args.output_dir)

    model.save_model(os.path.join(args.output_dir, "xgboost_cicids2017.json"))
    print(f"\nModel saved to {args.output_dir}/xgboost_cicids2017.json")
    print(f"Final macro F1: {macro_f1:.4f}")


if __name__ == "__main__":
    main()
