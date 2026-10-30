#!/usr/bin/env python3
"""Threat Watcher worker: dnstwist permutations and the optional URL classifier.

Protocol: one JSON object per line on stdin, one per line on stdout.
    {"id":"1","cmd":"permute","domain":"acme-corp.com"} -> {"id":"1","candidates":[...]}
    {"id":"2","url":"http://example.com/login"}         -> {"id":"2","label":1,"score":0.83,"domain":"example.com"}
    {"id":"3","cmd":"ping"}                             -> {"id":"3","ok":true}

The model is loaded lazily on the first classify request, so permutations work
even when no .pkl exists (ML_URL_MODEL / ML_URL_VECTORIZER).
"""
from __future__ import annotations

import json
import os
import re
import sys

MODEL_PATH = os.environ.get("ML_URL_MODEL", "ml/models/url_classifier.pkl")
VECT_PATH = os.environ.get("ML_URL_VECTORIZER", "ml/models/url_vectorizer.pkl")

_DOMAIN_RE = re.compile(r"(?:\w*://)?(?:.*\.)?([a-zA-Z0-9-]+\.[a-zA-Z]{1,}).*")


def trim(url: str) -> str:
    """Extract the registrable domain from a URL (legacy behavior)."""
    m = _DOMAIN_RE.match(url or "")
    return m.group(1) if m else (url or "")


class Model:
    """Lazy holder: None until first use, False once loading failed."""

    def __init__(self) -> None:
        self.model = None
        self.vectorizer = None
        self.state = None

    def load(self) -> bool:
        if self.state is not None:
            return self.state
        try:
            import joblib  # noqa: PLC0415

            self.model = joblib.load(MODEL_PATH)
            self.vectorizer = joblib.load(VECT_PATH)
            self.state = True
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write(f"model unavailable: {exc}\n")
            self.state = False
        return self.state


def classify(url: str, holder: Model) -> dict:
    if not holder.load():
        return {"label": None, "score": None, "domain": trim(url), "error": "model unavailable"}
    domain = trim(url)
    vec = holder.vectorizer.transform([domain])
    pred = int(holder.model.predict(vec)[0])
    score = None
    if hasattr(holder.model, "predict_proba"):
        proba = holder.model.predict_proba(vec)[0]
        score = float(proba[1] if len(proba) > 1 else proba[0])
    return {"label": pred, "score": score, "domain": domain}


def permute(domain: str) -> list[str]:
    import dnstwist  # noqa: PLC0415

    rows = dnstwist.run(domain=domain, format="list", registered=False, output=dnstwist.devnull)
    return [r if isinstance(r, str) else r.get("domain", "") for r in rows]


def reply(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main() -> int:
    holder = Model()
    reply({"ready": True})
    for raw in sys.stdin:
        line = raw.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as exc:
            reply({"error": f"bad json: {exc}"})
            continue
        rid = req.get("id")
        cmd = req.get("cmd")
        try:
            if cmd == "ping":
                reply({"id": rid, "ok": True})
            elif cmd == "permute":
                reply({"id": rid, "candidates": permute(req.get("domain", ""))})
            else:
                result = classify(req.get("url", ""), holder)
                result["id"] = rid
                reply(result)
        except ImportError as exc:
            reply({"id": rid, "error": f"{exc.name} not installed"})
        except Exception as exc:  # noqa: BLE001
            reply({"id": rid, "error": str(exc)})
    return 0


if __name__ == "__main__":
    sys.exit(main())
