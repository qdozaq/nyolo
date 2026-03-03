import { defaults } from "./defaults.js";

/** Category-grouped views of default rules */
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

/** All default rules — convenience preset for user configs */
export const recommended = [...defaults];

/**
 * Identity function for editor autocomplete / validation.
 * @param {import("./engine.js").Rule[]} rules
 * @returns {import("./engine.js").Rule[]}
 */
export function defineConfig(rules) {
  return rules;
}

export { defaults };
