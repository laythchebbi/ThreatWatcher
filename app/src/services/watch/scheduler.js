const { env } = require("../../config");
const logger = require("../../logger");
const { Domain } = require("../../models");

const CLAIM_EXPIRY_MS = 20 * 60 * 1000;

/**
 * Atomically claim one due domain. A claim older than 20 minutes is treated
 * as abandoned (crash mid-cycle) and can be re-taken.
 * @returns {Promise<any>} the claimed Domain document, or null
 */
function claimDomain(now) {
  return Domain.findOneAndUpdate(
    {
      nextWatchAt: { $lte: now },
      $or: [
        { watchingSince: null },
        { watchingSince: { $lt: new Date(now.getTime() - CLAIM_EXPIRY_MS) } },
      ],
    },
    { $set: { watchingSince: now } },
    { sort: { nextWatchAt: 1 }, new: true }
  );
}

/**
 * In-process scheduler: every `intervalMs` it claims up to `concurrency`
 * domains (minus those still running) and runs a cycle for each.
 * @param {{ runCycle: Function, deps: object, concurrency?: number, intervalMs?: number, now?: () => Date }} opts
 */
function createScheduler({
  runCycle,
  deps,
  concurrency = env.WATCH_CONCURRENCY,
  intervalMs = 60_000,
  now = () => new Date(),
}) {
  const running = new Set();
  let timer = null;

  async function tick() {
    let started = 0;
    while (running.size < concurrency) {
      const domain = await claimDomain(now());
      if (!domain) break;
      const job = runCycle(domain, { ...deps, now: now() })
        .catch((err) => logger.error({ err, domain: domain.name }, "cycle crashed"))
        .finally(() => running.delete(job));
      running.add(job);
      started += 1;
    }
    return started;
  }

  function start() {
    if (timer) return;
    timer = setInterval(
      () => tick().catch((err) => logger.error({ err }, "scheduler tick failed")),
      intervalMs
    );
    timer.unref();
    tick().catch((err) => logger.error({ err }, "scheduler tick failed"));
  }

  async function stop() {
    if (timer) clearInterval(timer);
    timer = null;
    await Promise.allSettled([...running]);
  }

  return { start, stop, tick };
}

module.exports = { claimDomain, createScheduler, CLAIM_EXPIRY_MS };
