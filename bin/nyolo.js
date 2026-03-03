#!/usr/bin/env node

/**
 * nyolo CLI entry point
 *
 * Usage:
 *   nyolo install     - install hook into ~/.claude/settings.json
 *   nyolo uninstall   - remove hook from ~/.claude/settings.json
 *   nyolo test        - run a quick self-test
 *   nyolo rules       - list active rules
 *   nyolo             - hook mode (reads stdin JSON, evaluates rules)
 */

import { evaluate } from "../src/engine.js";
import { loadRules } from "../src/rules.js";
import { resolveConfig } from "../src/config.js";
import { configure, log } from "../src/logger.js";
import { homedir } from "os";
import { join, dirname } from "path";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "fs";

const args = process.argv.slice(2);
const subcommand = args[0];

// If no subcommand and stdin is not a TTY, run as hook
if (!subcommand) {
  await runHook();
  process.exit(0);
}

switch (subcommand) {
  case "install":
    await runInstall();
    break;
  case "uninstall":
    await runUninstall();
    break;
  case "test":
    await runTest();
    break;
  case "rules":
    await runRules();
    break;
  default:
    console.error(`Unknown subcommand: ${subcommand}`);
    console.error("Usage: nyolo [install|uninstall|test|rules]");
    process.exit(1);
}

// --- Hook mode ---

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString();
}

async function runHook() {
  try {
    const input = await readStdin();
    const event = JSON.parse(input);

    const configs = resolveConfig(event.cwd);
    configure(configs.global || {});

    const rules = loadRules(configs);
    const result = evaluate(event.tool_name, event.tool_input, rules);

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
    log("error", `Hook error: ${err.message}`);
    process.exit(0);
  }
}

// --- Install ---

function getSettingsPath() {
  return join(homedir(), ".claude", "settings.json");
}

function getHookCmd() {
  return "npx nyolo";
}

async function runInstall() {
  const settingsPath = getSettingsPath();

  mkdirSync(dirname(settingsPath), { recursive: true });

  let settings = {};
  if (existsSync(settingsPath)) {
    try {
      settings = JSON.parse(readFileSync(settingsPath, "utf8"));
    } catch {
      console.error(`Error: could not parse ${settingsPath}`);
      process.exit(1);
    }
  }

  if (!settings.hooks) settings.hooks = {};
  if (!settings.hooks.PreToolUse) settings.hooks.PreToolUse = [];

  const hookCmd = getHookCmd();

  // Check if already installed
  const exists = settings.hooks.PreToolUse.some(g =>
    g.hooks?.some(h => h.command?.includes("nyolo"))
  );

  if (exists) {
    console.log("nyolo hook is already installed.");
    return;
  }

  settings.hooks.PreToolUse.push({
    matcher: "Bash|Edit|Write|WebFetch|WebSearch",
    hooks: [{
      type: "command",
      command: hookCmd,
    }],
  });

  writeFileSync(settingsPath, JSON.stringify(settings, null, 2));
  console.log(`nyolo hook installed to ${settingsPath}`);
  console.log(`Hook command: ${hookCmd}`);
}

// --- Uninstall ---

async function runUninstall() {
  const settingsPath = getSettingsPath();

  if (!existsSync(settingsPath)) {
    console.log("No settings file found. Nothing to uninstall.");
    return;
  }

  let settings;
  try {
    settings = JSON.parse(readFileSync(settingsPath, "utf8"));
  } catch {
    console.error(`Error: could not parse ${settingsPath}`);
    process.exit(1);
  }

  if (!settings.hooks?.PreToolUse) {
    console.log("nyolo hook is not installed.");
    return;
  }

  const before = settings.hooks.PreToolUse.length;
  settings.hooks.PreToolUse = settings.hooks.PreToolUse.filter(g =>
    !g.hooks?.some(h => h.command?.includes("nyolo"))
  );
  const after = settings.hooks.PreToolUse.length;

  if (before === after) {
    console.log("nyolo hook is not installed.");
    return;
  }

  writeFileSync(settingsPath, JSON.stringify(settings, null, 2));
  console.log(`nyolo hook removed from ${settingsPath}`);
}

// --- Test ---

async function runTest() {
  console.log("Running nyolo self-test...\n");

  const configs = resolveConfig(process.cwd());
  const rules = loadRules(configs);

  const tests = [
    { tool: "Bash", input: { command: "rm -rf /" }, expected: "deny", label: "rm -rf /" },
    { tool: "Bash", input: { command: "sudo apt-get update" }, expected: "deny", label: "sudo" },
    { tool: "Bash", input: { command: "ls -la" }, expected: "allow", label: "ls -la" },
    { tool: "Write", input: { file_path: "/project/.env" }, expected: "ask", label: "write .env" },
  ];

  let passed = 0;
  let failed = 0;

  for (const t of tests) {
    const result = evaluate(t.tool, t.input, rules);
    const ok = result.decision === t.expected;
    const status = ok ? "PASS" : "FAIL";
    console.log(`  [${status}] ${t.label}: ${result.decision} (expected ${t.expected})`);
    if (ok) passed++; else failed++;
  }

  console.log(`\n${passed} passed, ${failed} failed`);

  if (failed > 0) process.exit(1);
}

// --- Rules ---

async function runRules() {
  const configs = resolveConfig(process.cwd());
  const rules = loadRules(configs);

  console.log(`Active rules (${rules.length} total):\n`);

  // Group by category
  const byCategory = {};
  for (const rule of rules) {
    const cat = rule.category || "custom";
    if (!byCategory[cat]) byCategory[cat] = [];
    byCategory[cat].push(rule);
  }

  for (const [category, catRules] of Object.entries(byCategory)) {
    console.log(`  ${category}:`);
    for (const rule of catRules) {
      console.log(`    [${rule.action}] ${rule.name} — ${rule.reason}`);
    }
  }
}
