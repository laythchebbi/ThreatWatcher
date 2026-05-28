#!/usr/bin/env python3
"""URL classifier worker.

Protocol:
    stdin:  one JSON object per line, e.g. {"id":"abc","url":"http://example.com/login"}
    stdout: one JSON object per line, e.g. {"id":"abc","score":0.83,"label":1}

The script loads the pre-trained model once at startup and stays running.
A line `{"cmd":"ping"}` returns `{"ok":true}` for the bridge to verify health.

Model and vectorizer paths are read from env (set by the parent Node process):
    ML_URL_MODEL       Path to logreg pkl  (default: ml/models/url_classifier.pkl)
    ML_URL_VECTORIZER  Path to TF-IDF pkl  (default: ml/models/url_vectorizer.pkl)
"""
from __future__ import annotations

import json
import os
import re
import sys

import joblib

MODEL_PATH = os.environ.get("ML_URL_MODEL", "ml/models/url_classifier.pkl")
VECT_PATH = os.environ.get("ML_URL_VECTORIZER", "ml/models/url_vectorizer.pkl")

_DOMAIN_RE = re.compile(r"(?:\w*://)?(?:.*\.)?([a-zA-Z0-9-]+\.[a-zA-Z]{1,}).*")


def trim(url: str) -> str:
    """Extract the registrable domain from a URL (legacy behavior)."""
    m = _DOMAIN_RE.match(url or "")
    return m.group(1) if m else (url or "")


def classify(url: str, model, vectorizer) -> dict:
    domain = trim(url)
    vec = vectorizer.transform([domain])
    pred = int(model.predict(vec)[0])
    score = None
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(vec)[0]
        score = float(proba[1] if len(proba) > 1 else proba[0])
    return {"label": pred, "score": score, "domain": domain}


def main() -> int:
    try:
        model = joblib.load(MODEL_PATH)
        vectorizer = joblib.load(VECT_PATH)
    except Exception as exc:  # noqa: BLE001
        sys.stdout.write(json.dumps({"ready": False, "error": str(exc)}) + "\n")
        sys.stdout.flush()
        return 1

    sys.stdout.write(json.dumps({"ready": True}) + "\n")
    sys.stdout.flush()

    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as exc:
            sys.stdout.write(json.dumps({"error": f"bad json: {exc}"}) + "\n")
            sys.stdout.flush()
            continue

        rid = req.get("id")
        if req.get("cmd") == "ping":
            sys.stdout.write(json.dumps({"id": rid, "ok": True}) + "\n")
            sys.stdout.flush()
            continue

        url = req.get("url", "")
        try:
            result = classify(url, model, vectorizer)
            result["id"] = rid
            sys.stdout.write(json.dumps(result) + "\n")
        except Exception as exc:  # noqa: BLE001
            sys.stdout.write(json.dumps({"id": rid, "error": str(exc)}) + "\n")
        sys.stdout.flush()

    return 0


if __name__ == "__main__":
    sys.exit(main())
