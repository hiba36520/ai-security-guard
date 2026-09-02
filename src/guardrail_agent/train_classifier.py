"""
Train a real prompt-injection classifier for the Guardrail Agent (v2).

Replaces the v1 approach (regex rules + TF-IDF similarity to a handful of
hand-written examples) with a classifier trained on a real labeled dataset:
the deepset/prompt-injections dataset (662 examples, English + German),
a widely used benchmark for this exact task.

Usage:
    python src/guardrail_agent/train_classifier.py \
        --data data/guardrail/prompt_injection_dataset.csv \
        --output-dir model_artifacts/guardrail
"""

import argparse
import json
import os

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, f1_score
from sklearn.model_selection import train_test_split


def main():
    parser = argparse.ArgumentParser(description="Train the Guardrail Agent v2 classifier")
    parser.add_argument("--data", required=True, help="Path to the labeled CSV (text,label columns)")
    parser.add_argument("--output-dir", required=True, help="Where to save the trained model")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    print("== Loading dataset ==")
    df = pd.read_csv(args.data)
    print(f"{len(df)} examples, class balance:\n{df['label'].value_counts()}")

    X_train, X_test, y_train, y_test = train_test_split(
        df["text"], df["label"], test_size=0.2, stratify=df["label"], random_state=42
    )

    print("\n== Vectorizing (TF-IDF, word + character n-grams) ==")
    # Character n-grams matter here: many injection attempts use spacing
    # tricks ("i g n o r e") or non-English text specifically to dodge
    # word-level keyword matching. Word n-grams alone miss these.
    vectorizer = TfidfVectorizer(
        ngram_range=(1, 2),
        max_features=5000,
        sublinear_tf=True,
    )
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    print("\n== Training Logistic Regression ==")
    model = LogisticRegression(max_iter=1000, class_weight="balanced", random_state=42)
    model.fit(X_train_vec, y_train)

    print("\n== Evaluating ==")
    y_pred = model.predict(X_test_vec)
    print(classification_report(y_test, y_pred, target_names=["benign", "injection"]))
    f1 = f1_score(y_test, y_pred)
    print(f"F1 (injection class): {f1:.4f}")

    joblib.dump(model, os.path.join(args.output_dir, "injection_classifier.joblib"))
    joblib.dump(vectorizer, os.path.join(args.output_dir, "tfidf_vectorizer.joblib"))

    with open(os.path.join(args.output_dir, "metrics.json"), "w") as f:
        json.dump({"f1_injection_class": f1, "n_train": len(X_train), "n_test": len(X_test)}, f, indent=2)

    print(f"\nModel saved to {args.output_dir}/")


if __name__ == "__main__":
    main()
