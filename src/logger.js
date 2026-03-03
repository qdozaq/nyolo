/**
 * @typedef {"debug" | "info" | "warn" | "error" | "silent"} LogLevel
 *
 * @typedef {Object} LoggerConfig
 * @property {LogLevel} [logLevel]
 * @property {string | null} [logFile]
 */

/** @type {Record<LogLevel, number>} */
const LEVELS = { debug: 0, info: 1, warn: 2, error: 3, silent: 4 };

/** @type {LogLevel} */
let level = "warn";

/** @type {string | null} */
let logFile = null;

/**
 * Configure the logger.
 * @param {LoggerConfig} opts
 */
export function configure(opts = {}) {
  if (opts.logLevel) level = opts.logLevel;
  if (opts.logFile) logFile = opts.logFile;
}

/**
 * Log a message at the given level (writes to stderr).
 * @param {LogLevel} lvl
 * @param {string} message
 */
export function log(lvl, message) {
  if (LEVELS[lvl] < LEVELS[level]) return;
  const line = `[${new Date().toISOString()}] [${lvl.toUpperCase()}] ${message}`;
  process.stderr.write(line + "\n");
  if (logFile) {
    Bun.write(Bun.file(logFile), line + "\n").catch(() => {});
  }
}
