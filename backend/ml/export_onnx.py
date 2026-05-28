#!/usr/bin/env python3
"""Export the trained URL classifier to ONNX.

This is the last step of the M4 ML refresh — once the .onnx file lands, the
Node bridge can load it directly via `onnxruntime-node` and we retire the
Python child_process worker entirely.

Usage:
    pip install skl2onnx onnxruntime
    python backend/ml/export_onnx.py \
        --model ml/models/url_classifier.pkl \
        --vectorizer ml/models/url_vectorizer.pkl \
        --out ml/models/url_classifier.onnx

The output ONNX graph takes a single string input named `domain` and emits
`{label, probability}`. The Node loader in `src/services/ml-onnx.js` wraps
this with the same `classifyUrl(url)` API.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import joblib
from skl2onnx import to_onnx
from skl2onnx.common.data_types import StringTensorType


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser()
    p.add_argument("--model", required=True)
    p.add_argument("--vectorizer", required=True)
    p.add_argument("--out", required=True)
    return p.parse_args()


def main() -> int:
    args = parse_args()
    from sklearn.pipeline import Pipeline

    vec = joblib.load(args.vectorizer)
    clf = joblib.load(args.model)
    pipeline = Pipeline([("tfidf", vec), ("logreg", clf)])

    initial_types = [("domain", StringTensorType([None, 1]))]
    onx = to_onnx(pipeline, initial_types=initial_types, target_opset=15)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(onx.SerializeToString())
    print(f"saved → {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
