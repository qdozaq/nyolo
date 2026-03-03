#!/usr/bin/env node

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
import { resolveConfig } from "./src/config.js";
import { log } from "./src/logger.js";

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString();
}

try {
  // Read event from stdin
  const input = await readStdin();
  /** @type {HookEvent} */
  const event = JSON.parse(input);

  // Resolve config: flat rules array from nyolo.config.js files
  const rules = await resolveConfig(event.cwd);
  const result = evaluate(event.tool_name, event.tool_input, rules, { cwd: event.cwd });

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
