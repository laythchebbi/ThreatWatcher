const { env } = require("../config");
const logger = require("../logger");

const SLACK_API = "https://slack.com/api/chat.postMessage";

async function sendSlackNotification({ channel = "#threat-watcher", text }) {
  if (!env.SLACK_BOT_TOKEN) {
    logger.warn("SLACK_BOT_TOKEN not set — slack notification skipped");
    return { ok: false, skipped: true };
  }
  if (!text) throw new Error("text is required");

  const res = await fetch(SLACK_API, {
    method: "POST",
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      Authorization: `Bearer ${env.SLACK_BOT_TOKEN}`,
    },
    body: JSON.stringify({ channel, text }),
  });

  const body = /** @type {{ ok: boolean, error?: string }} */ (await res.json());
  if (!body.ok) {
    logger.error({ slackError: body.error, channel }, "slack postMessage failed");
    return { ok: false, error: body.error };
  }
  return { ok: true };
}

module.exports = { sendSlackNotification };
