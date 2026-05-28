/**
 * Structured HTTP error. Carries a status code, a stable machine-readable
 * `code`, and optional validation `issues`. The global error handler
 * (middleware/errors.js) reads these to shape the JSON response.
 */
class HttpError extends Error {
  /**
   * @param {string} message
   * @param {{ status?: number, code?: string, issues?: unknown[] }} [opts]
   */
  constructor(message, { status = 500, code = "error", issues } = {}) {
    super(message);
    this.name = "HttpError";
    /** @type {number} */
    this.status = status;
    /** @type {string} */
    this.code = code;
    if (issues) {
      /** @type {unknown[]} */
      this.issues = issues;
    }
  }
}

module.exports = HttpError;
