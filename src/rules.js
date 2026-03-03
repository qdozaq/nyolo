import { createRequire } from "module";
const require = createRequire(import.meta.url);
const defaults = require("./defaults.json");

/**
 * @typedef {Object} HookConfig
 * @property {boolean} [useDefaults] - Include default rules (default: true). Set to false to use only custom rules.
 * @property {import("./engine.js").DeclarativeRule[]} [rules] - Custom user rules (prepended before defaults)
 * @property {string[]} [disableDefaults] - Default rule names to disable
 * @property {boolean} [allowProjectOverrides] - Allow project configs to use "allow" rules and disableDefaults (default: false)
 * @property {import("./logger.js").LogLevel} [logLevel]
 * @property {string | null} [logFile]
 */

/**
 * Get default rules filtered by category names.
 * @param {string[]} [categories] - Category names to include; omit for all.
 * @returns {import("./engine.js").DeclarativeRule[]}
 */
export function getDefaults(categories) {
  if (!categories) return [...defaults];
  const set = new Set(categories);
  return defaults.filter((r) => set.has(r.category));
}

/**
 * Load and merge rules from global and project configs.
 *
 * Security model:
 * - Global config (trusted): full control — useDefaults, disableDefaults, allow/deny/ask rules
 * - Project config (untrusted): additive-only by default — only deny/ask rules honored
 * - Global can set allowProjectOverrides: true to relax project restrictions
 *
 * Evaluation order (first-match-wins):
 *   1. Project deny/ask rules (strictest first)
 *   2. Global custom rules
 *   3. Active defaults
 *
 * @param {import("./config.js").ResolvedConfigs} configs
 * @returns {import("./engine.js").DeclarativeRule[]}
 */
export function loadRules(configs = {}) {
  const { global: globalConfig, project: projectConfig } = configs;

  // Determine base defaults from global config
  let baseDefaults;
  if (globalConfig?.useDefaults === false) {
    baseDefaults = [];
  } else {
    const disabled = new Set(globalConfig?.disableDefaults || []);
    baseDefaults = defaults.filter((r) => !disabled.has(r.name));
  }

  const globalRules = globalConfig?.rules || [];

  // Project rules: security-filtered unless global opts in
  const allowOverrides = globalConfig?.allowProjectOverrides === true;
  let projectRules = projectConfig?.rules || [];

  if (!allowOverrides) {
    // Untrusted project: only deny/ask rules, ignore allow
    projectRules = projectRules.filter((r) => r.action === "deny" || r.action === "ask");
  } else {
    // Trusted: project can also disable defaults
    const projectDisabled = new Set(projectConfig?.disableDefaults || []);
    if (projectDisabled.size > 0) {
      baseDefaults = baseDefaults.filter((r) => !projectDisabled.has(r.name));
    }
  }

  // Order: project rules -> global rules -> defaults (first-match-wins)
  return [...projectRules, ...globalRules, ...baseDefaults];
}

/** Category-grouped views of default rules (computed from defaults.json) */
const byCategory = Object.groupBy(defaults, (r) => r.category);
export const filesystem = byCategory.filesystem ?? [];
export const cloud = byCategory.cloud ?? [];
export const network = byCategory.network ?? [];
export const git = byCategory.git ?? [];
export const database = byCategory.database ?? [];
export const system = byCategory.system ?? [];
export const container = byCategory.container ?? [];
export const protection = byCategory.protection ?? [];
export const sensitive = byCategory.sensitive ?? [];
export const warnings = byCategory.warnings ?? [];

export { defaults };
