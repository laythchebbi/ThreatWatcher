/**
 * ONNX-based URL classifier loader (M4 forward path).
 *
 * Loads `ml/models/url_classifier.onnx` and exposes a Promise<MlClassification>
 * `classify(url)` with the same shape as the Python-bridge worker. Once a
 * trained-on-sklearn-1.x .onnx file is produced (see ml/export_onnx.py), the
 * `server.js` boot path can switch from `ml-bridge.start()` to this loader,
 * retiring the Python child_process entirely.
 *
 * Lazy-required so the rest of the backend works without `onnxruntime-node`
 * installed during M1/M2/M3.
 */

const path = require("node:path");
const fs = require("node:fs");
const { env } = require("../config");
const logger = require("../logger");

let session = null;
let ort = null;

async function load() {
  if (session) return session;
  const onnxPath = path.resolve(__dirname, "../../", env.ML_URL_MODEL.replace(/\.pkl$/, ".onnx"));
  if (!fs.existsSync(onnxPath)) {
    throw new Error(`ONNX model not found at ${onnxPath} — run backend/ml/export_onnx.py`);
  }
  try {
    // Optional dependency — only present once the M4 ONNX path is enabled.
    // @ts-expect-error optional module, intentionally not in package.json yet
    ort = require("onnxruntime-node");
  } catch {
    throw new Error(
      "onnxruntime-node not installed — run `npm i onnxruntime-node` to enable the ONNX path"
    );
  }
  session = await ort.InferenceSession.create(onnxPath);
  logger.info({ model: onnxPath }, "onnx url classifier loaded");
  return session;
}

async function classifyUrl(url) {
  const s = await load();
  const input = new ort.Tensor("string", [String(url || "")], [1, 1]);
  const out = await s.run({ domain: input });
  // skl2onnx names outputs `label` and `probabilities`; defaults differ by exporter version.
  const label = Number(out.label?.data?.[0] ?? out[0]?.data?.[0] ?? 0);
  const proba = out.probabilities?.data || out.output_probability?.data || [];
  const score = proba.length ? Math.max(...proba) : null;
  return { label, score };
}

module.exports = { load, classifyUrl };
