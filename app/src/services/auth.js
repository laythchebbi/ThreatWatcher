const crypto = require("node:crypto");
const { env } = require("../config");
const User = require("../models/user");
const HttpError = require("../lib/http-error");
const mailer = require("../lib/mailer");
const { hashPassword, verifyPassword, DUMMY_HASH } = require("./password");

const TOKEN_TTL_MS = 60 * 60 * 1000;

function normaliseEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}

/** Random token for links; only its sha256 is stored. */
function createToken() {
  const token = crypto.randomBytes(32).toString("base64url");
  return { token, hash: hashToken(token) };
}

function hashToken(token) {
  return crypto.createHash("sha256").update(String(token)).digest("hex");
}

async function signup({ email, password }) {
  const normalised = normaliseEmail(email);
  const existing = await User.findOne({ email: normalised });
  if (existing) throw new HttpError("email_taken", { status: 409, code: "email_taken" });
  const user = await User.create({ email: normalised, passwordHash: await hashPassword(password) });
  await startVerify(user);
  return user;
}

/** Unknown email still pays one scrypt so timing does not reveal accounts. */
async function login({ email, password }) {
  const user = await User.findOne({ email: normaliseEmail(email) });
  if (!user) {
    await verifyPassword(password, await DUMMY_HASH);
    return null;
  }
  return (await verifyPassword(password, user.passwordHash)) ? user : null;
}

async function startVerify(user) {
  const { token, hash } = createToken();
  user.verifyTokenHash = hash;
  user.verifyTokenExpiresAt = new Date(Date.now() + TOKEN_TTL_MS);
  await user.save();
  await mailer.send({
    to: user.email,
    subject: "Verify your Threat Watcher email",
    text: `Confirm this address to start watching domains:\n${env.BASE_URL}/verify/${token}\n\nThe link works for one hour.`,
  });
}

async function completeVerify(token) {
  const user = await User.findOne({
    verifyTokenHash: hashToken(token),
    verifyTokenExpiresAt: { $gt: new Date() },
  });
  if (!user) return false;
  user.emailVerifiedAt = new Date();
  user.verifyTokenHash = undefined;
  user.verifyTokenExpiresAt = undefined;
  await user.save();
  return true;
}

/** Always resolves; mails only when the account exists. */
async function startReset(email) {
  const user = await User.findOne({ email: normaliseEmail(email) });
  if (!user) return;
  const { token, hash } = createToken();
  user.resetTokenHash = hash;
  user.resetTokenExpiresAt = new Date(Date.now() + TOKEN_TTL_MS);
  await user.save();
  await mailer.send({
    to: user.email,
    subject: "Reset your Threat Watcher password",
    text: `Choose a new password here:\n${env.BASE_URL}/reset/${token}\n\nThe link works once, for one hour. Ignore this if you did not ask for it.`,
  });
}

/** Single use: clears the token and bumps sessionVersion so every cookie is revoked. */
async function completeReset({ token, password }) {
  const user = await User.findOne({
    resetTokenHash: hashToken(token),
    resetTokenExpiresAt: { $gt: new Date() },
  });
  if (!user) return false;
  user.passwordHash = await hashPassword(password);
  user.resetTokenHash = undefined;
  user.resetTokenExpiresAt = undefined;
  user.sessionVersion += 1;
  await user.save();
  return true;
}

module.exports = {
  normaliseEmail,
  signup,
  login,
  startVerify,
  completeVerify,
  startReset,
  completeReset,
};
