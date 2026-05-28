#!/usr/bin/env python3
"""Web-content classifier worker.

Protocol:
    stdin:  {"id":"abc","url":"http://..."} OR {"id":"abc","html":"<html>..."}
    stdout: {"id":"abc","score":0.71,"label":-1,"features":{...}}

Labels follow the legacy convention:
     1  legitimate
     0  suspicious
    -1  phishing

Features are extracted from the URL/HTML directly. If a model file is
configured (ML_CONTENT_MODEL), it's used to produce a score; otherwise
the script returns the rule-based label without a probabilistic score.
"""
from __future__ import annotations

import json
import os
import re
import sys
from urllib.parse import urlparse

try:
    import joblib  # type: ignore
except ImportError:  # joblib is optional if no model is loaded
    joblib = None

MODEL_PATH = os.environ.get("ML_CONTENT_MODEL", "")

IPV4 = (
    r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
)
SHORTENERS = (
    r"bit\.ly|goo\.gl|t\.co|tinyurl|is\.gd|cli\.gs|ow\.ly|"
    r"buff\.ly|adf\.ly|bit\.do|cutt\.us|shorte\.st"
)


def having_ip(url: str) -> int:
    return -1 if re.search(IPV4, url) else 1


def url_length(url: str) -> int:
    n = len(url)
    if n < 54:
        return 1
    if n <= 75:
        return 0
    return -1


def shortening(url: str) -> int:
    return -1 if re.search(SHORTENERS, url) else 1


def at_symbol(url: str) -> int:
    return -1 if "@" in url else 1


def double_slash(url: str) -> int:
    return -1 if url.rfind("//") > 6 else 1


def prefix_suffix(host: str) -> int:
    return -1 if "-" in host else 1


def sub_domain(url: str) -> int:
    host = urlparse(url).hostname or ""
    dots = host.count(".")
    if dots <= 1:
        return 1
    if dots == 2:
        return 0
    return -1


def https_token(url: str) -> int:
    parsed = urlparse(url)
    return 1 if parsed.scheme == "https" else -1


def extract_features(url: str) -> dict:
    host = urlparse(url).hostname or ""
    return {
        "ip": having_ip(url),
        "url_length": url_length(url),
        "shortener": shortening(url),
        "at_symbol": at_symbol(url),
        "double_slash": double_slash(url),
        "prefix_suffix": prefix_suffix(host),
        "sub_domain": sub_domain(url),
        "https": https_token(url),
    }


def rule_label(features: dict) -> int:
    score = sum(features.values())
    if score >= 5:
        return 1
    if score >= 0:
        return 0
    return -1


def classify(url: str, model) -> dict:
    feats = extract_features(url)
    label = rule_label(feats)
    score = None
    if model is not None:
        try:
            vec = list(feats.values())
            pred = int(model.predict([vec])[0])
            label = pred
            if hasattr(model, "predict_proba"):
                proba = model.predict_proba([vec])[0]
                score = float(max(proba))
        except Exception:  # noqa: BLE001
            pass
    return {"label": label, "score": score, "features": feats}


def main() -> int:
    model = None
    if MODEL_PATH and joblib is not None and os.path.exists(MODEL_PATH):
        try:
            model = joblib.load(MODEL_PATH)
        except Exception as exc:  # noqa: BLE001
            sys.stdout.write(json.dumps({"ready": False, "error": str(exc)}) + "\n")
            sys.stdout.flush()
            return 1

    sys.stdout.write(json.dumps({"ready": True, "model": bool(model)}) + "\n")
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
            result = classify(url, model)
            result["id"] = rid
            sys.stdout.write(json.dumps(result) + "\n")
        except Exception as exc:  # noqa: BLE001
            sys.stdout.write(json.dumps({"id": rid, "error": str(exc)}) + "\n")
        sys.stdout.flush()

    return 0


if __name__ == "__main__":
    sys.exit(main())
