"""
train.py — Spam Classifier Training Script
-------------------------------------------
Dataset: "Spam or Not Spam Dataset" from Kaggle
  https://www.kaggle.com/datasets/ozlerhakan/spam-or-not-spam-dataset
  File: spam_or_not_spam.csv  (columns: email, label)
  Place the CSV inside the /data/ folder before running.

Trains two models and saves the better one:
  - Multinomial Naive Bayes   (fast, strong baseline)
  - Logistic Regression       (usually better on clean datasets)

Pipeline: TF-IDF (with bigrams) → Classifier
Saved to: models/spam_model.pkl  +  models/vectorizer.pkl
"""

import os
import sys
import joblib
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (classification_report, confusion_matrix,
                              accuracy_score)
from sklearn.pipeline import Pipeline

# ── Paths ──────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
DATA_PATH  = os.path.join(BASE_DIR, "data", "spam_or_not_spam.csv")
MODEL_DIR  = os.path.join(BASE_DIR, "models")
MODEL_PATH = os.path.join(MODEL_DIR, "spam_model.pkl")

os.makedirs(MODEL_DIR, exist_ok=True)


def load_data():
    if not os.path.exists(DATA_PATH):
        print(f"""
ERROR: Dataset not found at: {DATA_PATH}

Steps to get the dataset:
  1. Go to https://www.kaggle.com/datasets/ozlerhakan/spam-or-not-spam-dataset
  2. Download spam_or_not_spam.csv
  3. Place it inside the data/ folder of this project
  4. Re-run: python train.py
""")
        sys.exit(1)

    df = pd.read_csv(DATA_PATH)

    # Normalize column names (dataset uses 'email' and 'label')
    df.columns = [c.lower().strip() for c in df.columns]
    if "email" not in df.columns or "label" not in df.columns:
        # Try alternate column names
        col_map = {}
        for c in df.columns:
            if "mail" in c or "text" in c or "message" in c:
                col_map[c] = "email"
            elif "label" in c or "spam" in c or "class" in c:
                col_map[c] = "label"
        df = df.rename(columns=col_map)

    df = df[["email", "label"]].dropna()
    df["email"] = df["email"].astype(str)
    df["label"] = df["label"].astype(int)   # 1 = spam, 0 = ham

    print(f"[Data] Loaded {len(df)} samples")
    print(f"[Data] Spam: {df['label'].sum()} | Ham: {(df['label']==0).sum()}")
    return df


def build_pipeline(classifier):
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            strip_accents="unicode",
            analyzer="word",
            token_pattern=r"\b[a-zA-Z]{2,}\b",
            ngram_range=(1, 2),
            max_features=50000,
            sublinear_tf=True,
        )),
        ("clf", classifier),
    ])


def train():
    df = load_data()
    X = df["email"]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    models = {
        "Naive Bayes":        build_pipeline(MultinomialNB(alpha=0.1)),
        "Logistic Regression": build_pipeline(
            LogisticRegression(C=5, max_iter=1000, random_state=42)
        ),
    }

    best_model = None
    best_acc   = 0.0
    best_name  = ""

    for name, pipeline in models.items():
        print(f"\n[Train] Training {name}...")
        pipeline.fit(X_train, y_train)

        y_pred = pipeline.predict(X_test)
        acc    = accuracy_score(y_test, y_pred)

        print(f"[{name}] Accuracy : {acc:.4f}")
        print(classification_report(y_test, y_pred,
                                     target_names=["Ham", "Spam"]))

        # Cross-validation
        cv_scores = cross_val_score(pipeline, X, y, cv=5, scoring="accuracy")
        print(f"[{name}] CV Accuracy: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

        if acc > best_acc:
            best_acc   = acc
            best_model = pipeline
            best_name  = name

    print(f"\n[Train] ✅ Best model: {best_name} (accuracy: {best_acc:.4f})")
    print(f"[Train] Saving to {MODEL_PATH}")
    joblib.dump(best_model, MODEL_PATH)
    print("[Train] Done! Model saved successfully.")
    return best_model


def load_model():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"No trained model found at {MODEL_PATH}. Run: python train.py"
        )
    return joblib.load(MODEL_PATH)


def predict(model, text: str) -> dict:
    """
    Returns:
      label       : 'spam' or 'ham'
      confidence  : float 0–1 (probability of the predicted class)
      spam_prob   : float 0–1
      ham_prob    : float 0–1
    """
    proba = model.predict_proba([text])[0]
    ham_prob, spam_prob = proba[0], proba[1]
    label = "spam" if spam_prob > 0.5 else "ham"
    confidence = spam_prob if label == "spam" else ham_prob
    return {
        "label":      label,
        "confidence": round(float(confidence), 4),
        "spam_prob":  round(float(spam_prob), 4),
        "ham_prob":   round(float(ham_prob), 4),
    }


if __name__ == "__main__":
    train()
