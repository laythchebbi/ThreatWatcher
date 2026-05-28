/**
 * Shared JSDoc typedefs. Other modules reference these with a JSDoc
 * `@type` annotation pointing at this file's relative path, e.g.
 * the `ScoredDomain` typedef defined below.
 *
 * Not exported at runtime — this module is empty at runtime.
 */

/**
 * @typedef {Object} ScoredDomain
 * @property {string} domain      The lookalike domain.
 * @property {number} similarity  0..1 Dice coefficient against the reference.
 * @property {boolean} [punycode] Has an `xn--` marker.
 * @property {boolean} [substring] Reference label appears in this domain.
 * @property {number|null} [mlLabel] ML classifier label (0 safe, 1 malicious).
 * @property {number|null} [mlScore] ML classifier probability 0..1.
 */

/**
 * @typedef {Object} SecureScoreInput
 * @property {boolean} activeServer
 * @property {boolean} substring
 * @property {boolean} idn
 * @property {number}  visualSimilarity  0..1.
 */

/**
 * @typedef {Object} MlClassification
 * @property {number}   label    Integer class label.
 * @property {number|null} score Probability of the predicted class.
 * @property {string}   [domain] Echoed back from the worker for URL classifier.
 * @property {object}   [features] Echoed feature map for content classifier.
 */

/**
 * @typedef {import("express").Request & {
 *   id: string,
 *   auth?: { sub: string, email?: string, role?: string },
 * }} AuthedRequest
 */

module.exports = {};
