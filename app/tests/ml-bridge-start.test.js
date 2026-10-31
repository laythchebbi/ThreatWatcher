// A worker that dies before its first line must reject start(), never hang it.
process.env.PYTHON_BIN = "/usr/bin/false";
require("./helpers/env");
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { Worker } = require("../src/services/ml-bridge");

test("Worker.start rejects when the process exits before becoming ready", async () => {
  const w = new Worker("dead", "/nonexistent.py");
  await assert.rejects(
    Promise.race([
      w.start(),
      new Promise((_, rej) => setTimeout(() => rej(new Error("hung")), 5000)),
    ]),
    (err) => !/hung/.test(err.message)
  );
});
