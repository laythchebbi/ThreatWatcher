const path = require("node:path");
const { spawn } = require("node:child_process");
const readline = require("node:readline");
const crypto = require("node:crypto");
const { env } = require("../config");
const logger = require("../logger");

const ML_DIR = path.resolve(__dirname, "../../ml");
const SCRIPTS = {
  url: path.join(ML_DIR, "url_classifier.py"),
};

class Worker {
  constructor(name, script, modelEnv = {}) {
    this.name = name;
    this.script = script;
    this.modelEnv = modelEnv;
    this.proc = null;
    this.rl = null;
    this.pending = new Map();
    this.ready = false;
    this.everReady = false;
    this.shutdown = false;
    this.restartDelayMs = 1000;
  }

  async start() {
    return new Promise((resolve, reject) => {
      const proc = spawn(env.PYTHON_BIN, [this.script], {
        cwd: path.resolve(__dirname, "../.."),
        env: { ...process.env, ...this.modelEnv, PYTHONUNBUFFERED: "1" },
        stdio: ["pipe", "pipe", "pipe"],
      });
      this.proc = proc;

      proc.stderr.on("data", (chunk) => {
        logger.warn({ worker: this.name, stderr: chunk.toString().trim() }, "ml worker stderr");
      });
      proc.on("error", (err) => {
        logger.error({ err, worker: this.name }, "ml worker spawn error");
        if (!this.ready) reject(err);
      });
      proc.on("exit", (code, signal) => {
        logger.warn({ worker: this.name, code, signal }, "ml worker exited");
        this.ready = false;
        for (const { reject: rej } of this.pending.values()) {
          rej(new Error(`ml worker ${this.name} exited`));
        }
        this.pending.clear();
        // Only restart a worker that once worked; one that never became ready
        // (missing model, broken venv) would just loop forever at 30s.
        if (!this.shutdown && this.everReady) {
          setTimeout(() => this.start().catch(() => {}), this.restartDelayMs);
          this.restartDelayMs = Math.min(this.restartDelayMs * 2, 30_000);
        }
      });

      this.rl = readline.createInterface({ input: proc.stdout });
      let firstLine = true;
      this.rl.on("line", (line) => {
        let msg;
        try {
          msg = JSON.parse(line);
        } catch {
          logger.warn({ worker: this.name, line }, "ml worker non-json line");
          return;
        }
        if (firstLine) {
          firstLine = false;
          if (msg.ready) {
            this.ready = true;
            this.everReady = true;
            this.restartDelayMs = 1000;
            logger.info({ worker: this.name }, "ml worker ready");
            resolve();
          } else {
            logger.error({ worker: this.name, error: msg.error }, "ml worker startup failed");
            reject(new Error(msg.error || "ml worker startup failed"));
          }
          return;
        }
        const { id } = msg;
        if (!id) return;
        const handle = this.pending.get(id);
        if (!handle) return;
        this.pending.delete(id);
        clearTimeout(handle.timer);
        if (msg.error) handle.reject(new Error(msg.error));
        else handle.resolve(msg);
      });
    });
  }

  classify(payload, { timeoutMs = 5000 } = {}) {
    if (!this.ready || !this.proc) {
      return Promise.reject(new Error(`ml worker ${this.name} not ready`));
    }
    const id = crypto.randomUUID();
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`ml worker ${this.name} timeout`));
      }, timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
      this.proc.stdin.write(JSON.stringify({ id, ...payload }) + "\n");
    });
  }

  async stop() {
    this.shutdown = true;
    if (!this.proc) return;
    this.proc.stdin.end();
    await new Promise((r) => this.proc.once("exit", r));
  }
}

const workers = {
  url: new Worker("url", SCRIPTS.url, { ML_URL_MODEL: env.ML_URL_MODEL }),
};

async function start() {
  const tasks = Object.values(workers).map((w) =>
    w.start().catch((err) => {
      logger.warn(
        { err: { message: err.message }, worker: w.name },
        "ml worker start failed; running without it"
      );
    })
  );
  await Promise.all(tasks);
}

async function stop() {
  await Promise.all(Object.values(workers).map((w) => w.stop().catch(() => {})));
}

function classifyUrl(url, opts) {
  return workers.url.classify({ url }, opts);
}

function readiness() {
  return Object.fromEntries(Object.entries(workers).map(([k, w]) => [k, w.ready]));
}

module.exports = { start, stop, classifyUrl, readiness };
