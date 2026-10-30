const { env, isProd } = require("../config");
const logger = require("../logger");

/** Sent mail in dev/test lands here so tests can read tokens. */
const outbox = [];

/**
 * Send a plain-text email. Without SMTP_URL the message is logged and kept in
 * `outbox` (dev mode). Plan 3 adds the nodemailer transport behind SMTP_URL.
 * @param {{ to: string, subject: string, text: string }} msg
 */
async function send(msg) {
  if (!env.SMTP_URL) {
    outbox.push(msg);
    logger.info({ to: msg.to, subject: msg.subject }, "mail (not sent: SMTP_URL unset)");
    if (!isProd) logger.debug({ text: msg.text }, "mail body");
    return;
  }
  throw new Error("SMTP transport arrives in Plan 3");
}

function _reset() {
  outbox.length = 0;
}

module.exports = { send, outbox, _reset };
