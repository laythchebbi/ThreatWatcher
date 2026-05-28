#!/usr/bin/env python3
"""Retrain the URL classifier on scikit-learn 1.x.

Reads a labeled CSV with columns `url,label` (label 0=safe, 1=malicious) and
produces:

    ml/models/url_classifier.pkl        sklearn LogisticRegression
    ml/models/url_vectorizer.pkl        TF-IDF vectorizer
    ml/models/url_classifier.metrics.json
                                        accuracy / precision / recall / f1

Usage:
    python backend/ml/train_url_classifier.py \
        --data data/labeled_urls.csv \
        --out-dir ml/models

Notes:
- Mirrors the legacy `trim(url)` + token logic from the 2022 Flask app.
- After this lands, run `export_onnx.py` to produce a portable .onnx file the
  Node side can load via `onnxruntime-node`, retiring the Python bridge (M4).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

_DOMAIN_RE = re.compile(r"(?:\w*://)?(?:.*\.)?([a-zA-Z0-9-]+\.[a-zA-Z]{1,}).*")


def trim(url: str) -> str:
    m = _DOMAIN_RE.match(url or "")
    return m.group(1) if m else (url or "")


def tokens(input_str: str) -> list[str]:
    """Replicates the legacy tokenizer: split by /, -, and ."""
    out: list[str] = []
    for piece in str(input_str).split("/"):
        for tok in piece.split("-"):
            out.extend(tok.split("."))
    return [t for t in set(out) if t and t != "com"]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--data", required=True, help="CSV with columns url,label")
    p.add_argument("--out-dir", default="ml/models")
    p.add_argument("--test-size", type=float, default=0.2)
    p.add_argument("--random-state", type=int, default=42)
    return p.parse_args()


def main() -> int:
    args = parse_args()
    df = pd.read_csv(args.data)
    if not {"url", "label"}.issubset(df.columns):
        print("CSV must have columns: url,label", file=sys.stderr)
        return 1

    df["domain"] = df["url"].astype(str).map(trim)
    X = df["domain"].tolist()
    y = df["label"].astype(int).to_numpy()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=args.random_state, stratify=y
    )

    vectorizer = TfidfVectorizer(tokenizer=tokens, lowercase=False, ngram_range=(1, 2), min_df=2)
    Xv_train = vectorizer.fit_transform(X_train)
    Xv_test = vectorizer.transform(X_test)

    model = LogisticRegression(max_iter=2000, n_jobs=-1, solver="liblinear")
    model.fit(Xv_train, y_train)

    y_pred = model.predict(Xv_test)
    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1": float(f1_score(y_test, y_pred, zero_division=0)),
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "n_features": int(Xv_train.shape[1]),
    }
    print(classification_report(y_test, y_pred, zero_division=0))

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, out_dir / "url_classifier.pkl")
    joblib.dump(vectorizer, out_dir / "url_vectorizer.pkl")
    (out_dir / "url_classifier.metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"saved → {out_dir}/url_classifier.pkl, url_vectorizer.pkl, url_classifier.metrics.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
