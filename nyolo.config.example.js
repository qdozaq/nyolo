// nyolo.config.js — ESLint-style flat config for Claude Code safety guardrails
//
// Place this file at:
//   ~/.claude/nyolo.config.js     (global — composed via imports, IS the base rule set)
//   <project>/nyolo.config.js     (project — lightweight additions, no install needed)
//
// The config exports a flat array of rules. First matching rule wins.
// Project rules are always evaluated before global/default rules.

// ─── Project config (no imports needed, defaults auto-appended) ─────────────

export default [
  // Your custom rules go first (evaluated before defaults)

  // Example: allow terraform plan (read-only)
  // {
  //   name: "allow-terraform-plan",
  //   tool: "Bash",
  //   match: { command: "terraform plan*" },
  //   action: "allow",
  //   reason: "terraform plan is read-only",
  // },

  // Example: allow aws s3 ls (read-only listing)
  // {
  //   name: "allow-aws-s3-ls",
  //   tool: "Bash",
  //   match: { command: "aws s3 ls*" },
  //   action: "allow",
  //   reason: "listing is read-only",
  // },

  // Example: callback rule for custom matching logic
  // (toolName, toolInput, { cwd }) => {
  //   if (toolName === "Bash" && toolInput.command?.includes("my-sensitive-cmd")) {
  //     return { action: "deny", reason: "custom rule: my-sensitive-cmd is not allowed" };
  //   }
  //   return null; // skip — continue to next rule
  // },
];
// Recommended defaults are auto-appended after these rules.
// To suppress defaults, add: export const noDefaults = true;

// ─── Global config examples (uses imports, requires nyolo installed) ────────

// Option A: All defaults + custom rules
// import { recommended } from 'nyolo';
// export default [
//   { name: "allow-deploy", tool: "Bash", match: { command: "*deploy.sh*" }, action: "allow", reason: "Trusted" },
//   ...recommended,
// ];

// Option B: Only specific categories
// import { filesystem, git, defineConfig } from 'nyolo';
// export default defineConfig([...filesystem, ...git]);
