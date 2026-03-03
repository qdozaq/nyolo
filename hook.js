#!/usr/bin/env bun

/**
 * @typedef {Object} HookEvent
 * @property {string} session_id
 * @property {string} transcript_path
 * @property {string} cwd
 * @property {string} permission_mode
 * @property {string} hook_event_name
 * @property {string} tool_name
 * @property {Record<string, any>} tool_input
 * @property {string} tool_use_id
 */

import { evaluate } from "./src/engine.js";
import { loadRules } from "./src/rules.js";
import { resolveConfig } from "./src/config.js";
import { configure, log } from "./src/logger.js";

try {
  // Read event from stdin
  const input = await Bun.stdin.text();
  /** @type {HookEvent} */
  const event = JSON.parse(input);

  // Load configs: global (trusted) + project (untrusted, additive-only)
  const configs = resolveConfig(event.cwd);
  configure(configs.global || {});

  // Load and evaluate rules (project deny/ask only unless global opts in)
  const rules = loadRules(configs);
  const result = evaluate(event.tool_name, event.tool_input, rules);

  // Output decision
  if (result.decision === "deny" || result.decision === "ask") {
    const summary = event.tool_name === "Bash"
      ? event.tool_input.command?.substring(0, 80)
      : event.tool_input.file_path || "";

    log("warn", `BLOCKED [${result.rule}] tool=${event.tool_name} input="${summary}"`);

    const output = {
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: result.decision,
        permissionDecisionReason: result.reason,
      },
    };
    process.stdout.write(JSON.stringify(output));
  } else {
    log("debug", `ALLOWED tool=${event.tool_name}`);
  }

  process.exit(0);
} catch (err) {
  // Fail open: if the hook itself errors, allow the action
  log("error", `Hook error: ${err.message}`);
  process.exit(0);
}
