import { homedir, tmpdir } from "os";
import { join } from "path";
import { existsSync, copyFileSync, mkdtempSync, rmSync } from "fs";
import { pathToFileURL } from "url";
import { recommended } from "./rules.js";

/**
 * @typedef {Object} ConfigResult
 * @property {import("./engine.js").DeclarativeRule[]} rules
 * @property {boolean} noDefaults - If true, do not auto-append default rules
 */

/**
 * Dynamically import a JS config file.
 * Copies to a unique temp path before importing to bypass Bun's ESM cache
 * (Bun ignores query strings on file:// URLs for cache invalidation).
 * @param {string} filePath
 * @returns {Promise<ConfigResult | null>}
 */
async function loadConfigFile(filePath) {
  try {
    if (!existsSync(filePath)) return null;
    const tempDir = mkdtempSync(join(tmpdir(), "nyolo-cfg-"));
    const tempFile = join(tempDir, "nyolo.config.js");
    copyFileSync(filePath, tempFile);
    try {
      const mod = await import(pathToFileURL(tempFile).href);
      const rules = mod.default;
      if (!Array.isArray(rules)) return null;
      return { rules, noDefaults: mod.noDefaults === true };
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  } catch {
    return null;
  }
}

/**
 * Resolve global and project configs, merge into a flat rules array.
 *
 * Resolution:
 *   1. Global: ~/.claude/nyolo.config.js (composed via imports, IS the base)
 *   2. Project: <cwd>/nyolo.config.js (lightweight additions, prepended)
 *
 * Merge order (first-match-wins):
 *   [...projectRules, ...base]
 *
 * Base rules:
 *   - If a global config exists, it IS the base (no defaults auto-appended)
 *   - If no global config, `recommended` defaults are used as the base
 *   - Project configs can export `noDefaults = true` to suppress auto-appended defaults
 *
 * @param {string} cwd - Working directory
 * @param {Object} [opts]
 * @param {string} [opts.globalConfigPath] - Override global config path (for testing)
 * @returns {Promise<import("./engine.js").DeclarativeRule[]>}
 */
export async function resolveConfig(cwd, opts = {}) {
  const globalPath = opts.globalConfigPath ?? join(homedir(), ".claude", "nyolo.config.js");
  const projectPath = cwd ? join(cwd, "nyolo.config.js") : null;

  const globalResult = await loadConfigFile(globalPath);
  const projectResult = projectPath ? await loadConfigFile(projectPath) : null;

  // No configs at all — use recommended defaults
  if (!globalResult && !projectResult) {
    return recommended;
  }

  const projectRules = projectResult?.rules ?? [];

  // Determine base: global config if it exists, otherwise recommended defaults
  // (unless project opts out with noDefaults)
  let base;
  if (globalResult) {
    base = globalResult.rules;
  } else if (projectResult?.noDefaults) {
    base = [];
  } else {
    base = recommended;
  }

  return [...projectRules, ...base];
}
