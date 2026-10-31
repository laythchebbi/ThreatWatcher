const { env, isProd } = require("../config");
const logger = require("../logger");

/** Sent mail in dev/test lands here so tests can read tokens. */
const outbox = [];

if (env.SMTP_URL) {
  logger.warn("SMTP_URL is set but the SMTP transport arrives in Plan 3; mail is logged, not sent");
}

/**
 * Send a plain-text email. Until Plan 3 wires nodemailer, every message is
 * kept in `outbox` and logged. Outside production the full text is logged at
 * info, so a developer can copy the verification or reset link from the log.
 * @param {{ to: string, subject: string, text: string }} msg
 */
async function send(msg) {
  outbox.push(msg);
  if (isProd)
    logger.info({ to: msg.to, subject: msg.subject }, "mail (not sent: no transport yet)");
  else logger.info({ to: msg.to, subject: msg.subject, text: msg.text }, "mail (dev: not sent)");
}

function _reset() {
  outbox.length = 0;
}

module.exports = { send, outbox, _reset };
