# Backend ML

Two distinct dependency sets and two distinct workflows.

## Runtime (M1) — Python child_process workers

Pinned to **scikit-learn 0.22.1** to keep the legacy `.pkl` files working.

```bash
pip install -r backend/ml/requirements.txt
```

The Node `src/services/ml-bridge.js` spawns one persistent Python worker per
classifier on app start. Each worker reads JSON-per-line on stdin and emits
JSON-per-line on stdout:

```json
{"id":"abc","url":"http://example.com/login"}
{"id":"abc","score":0.83,"label":1,"domain":"example.com"}
```

Workers:

- `url_classifier.py` — loads `models/url_classifier.pkl` + `models/url_vectorizer.pkl`.
- `content_classifier.py` — feature extraction (40+ heuristics) + optional model
  scoring if `ML_CONTENT_MODEL` is set.

Pre-trained `.pkl` files are **not committed** (`.gitignore`d). Drop them into
`backend/ml/models/`, or train your own (see below).

## Retrain (M4) — sklearn 1.x

Separate, modern dependency set:

```bash
pip install -r backend/ml/requirements-train.txt
python backend/ml/train_url_classifier.py \
    --data data/labeled_urls.csv \
    --out-dir backend/ml/models
```

The CSV must have columns `url,label` (0=safe, 1=malicious). The script writes:

- `backend/ml/models/url_classifier.pkl`
- `backend/ml/models/url_vectorizer.pkl`
- `backend/ml/models/url_classifier.metrics.json`

⚠️ The new `.pkl` is **not** compatible with the runtime requirements above.
After retraining, either:

- Bump `requirements.txt` to sklearn 1.x and re-pin, **or**
- Export to ONNX and switch the bridge — see below (recommended).

## Export to ONNX (M4 — retire Python bridge)

```bash
python backend/ml/export_onnx.py \
    --model backend/ml/models/url_classifier.pkl \
    --vectorizer backend/ml/models/url_vectorizer.pkl \
    --out backend/ml/models/url_classifier.onnx
```

Then on the Node side:

```bash
npm --prefix backend i onnxruntime-node
```

Switch `src/server.js` from `mlBridge.start()` to `mlOnnx.load()` (see
`src/services/ml-onnx.js`). The Python worker is no longer needed; backend has
zero Python at runtime.

## File layout

```
backend/ml/
├── requirements.in           top-level runtime deps (sklearn 0.22.1)
├── requirements.txt          pinned (output of pip-compile)
├── requirements-train.txt    M4 retrain stack (sklearn 1.x, skl2onnx)
├── url_classifier.py         runtime worker (Python bridge)
├── content_classifier.py     runtime worker
├── train_url_classifier.py   M4 retrain script
├── export_onnx.py            M4 ONNX export
└── models/                   .pkl / .onnx artifacts (gitignored)
```
