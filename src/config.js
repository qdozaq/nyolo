import { homedir } from "os";
import { join } from "path";
import { readFileSync } from "fs";

/**
 * @typedef {Object} PermissionsConfig
 * @property {boolean} [useDefaults] - Include default rules (default: true)
 * @property {import("./engine.js").DeclarativeRule[]} [rules] - Custom rules (prepended before defaults)
 * @property {string[]} [disableDefaults] - Default rule names to disable
 * @property {boolean} [allowProjectOverrides] - Allow project configs to use "allow" rules and disableDefaults (default: false)
 * @property {import("./logger.js").LogLevel} [logLevel]
 * @property {string | null} [logFile]
 */

/**
 * @typedef {Object} ResolvedConfigs
 * @property {PermissionsConfig | null} global - Global config (~/.claude/permissions.json or env var)
 * @property {PermissionsConfig | null} project - Project config (<cwd>/.claude-permissions.json)
 */

/**
 * Strip single-line (//) and multi-line comments from JSON string.
 * Preserves strings containing // or comment-like content.
 * @param {string} text
 * @returns {string}
 */
export function stripJsonComments(text) {
  let result = "";
  let i = 0;
  let inString = false;

  while (i < text.length) {
    if (inString) {
      if (text[i] === "\\" && i + 1 < text.length) {
        result += text[i] + text[i + 1];
        i += 2;
        continue;
      }
      if (text[i] === '"') inString = false;
      result += text[i++];
    } else if (text[i] === '"') {
      inString = true;
      result += text[i++];
    } else if (text[i] === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
    } else if (text[i] === "/" && text[i + 1] === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i += 2;
    } else {
      result += text[i++];
    }
  }
  return result;
}

/**
 * Read and parse a JSONC file (JSON with comments).
 * @param {string} filePath
 * @returns {PermissionsConfig | null}
 */
function parseJsonc(filePath) {
  const text = readFileSync(filePath, "utf-8");
  return JSON.parse(stripJsonComments(text));
}

/**
 * Try to parse a config file, returning null on any error.
 * @param {string} filePath
 * @returns {PermissionsConfig | null}
 */
function tryParseConfig(filePath) {
  try {
    return parseJsonc(filePath);
  } catch {
    return null;
  }
}

/**
 * Resolve global and project configs separately.
 *
 * Global config (trusted, user-controlled):
 *   1. $CLAUDE_PERMISSIONS_CONFIG env var
 *   2. ~/.claude/permissions.json
 *
 * Project config (untrusted, may come from a cloned repo):
 *   3. <cwd>/.claude-permissions.json
 *
 * @param {string} cwd - Working directory from the hook event
 * @returns {ResolvedConfigs}
 */
export function resolveConfig(cwd) {
  // Global: env var takes priority, then ~/.claude/permissions.json
  // Support NYOLO_CONFIG, CLAUDE_PERMISSIONS_CONFIG, and legacy CLAUDE_HOOK_CONFIG
  let envPath = process.env.NYOLO_CONFIG || process.env.CLAUDE_PERMISSIONS_CONFIG;
  if (!envPath && process.env.CLAUDE_HOOK_CONFIG) {
    envPath = process.env.CLAUDE_HOOK_CONFIG;
    process.stderr.write("[DEPRECATION] CLAUDE_HOOK_CONFIG is deprecated, use NYOLO_CONFIG instead\n");
  }

  const globalConfig =
    (envPath && tryParseConfig(envPath)) ||
    tryParseConfig(join(homedir(), ".claude", "permissions.json"));

  // Project: <cwd>/.claude-permissions.json
  const projectConfig = cwd
    ? tryParseConfig(join(cwd, ".claude-permissions.json"))
    : null;

  return { global: globalConfig, project: projectConfig };
}
