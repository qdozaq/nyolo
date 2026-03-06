import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { resolveConfig } from "../src/config.js";
import { evaluate } from "../src/engine.js";
import { join } from "path";
import { mkdirSync, writeFileSync, rmSync, existsSync } from "fs";
import { tmpdir } from "os";

// Use a temp directory for test configs
const testDir = join(tmpdir(), `nyolo-config-test-${Date.now()}`);
// Ensure tests don't pick up the real global config
const noGlobal = { globalConfigPath: join(testDir, "__no_global_config.js") };

beforeEach(() => {
  mkdirSync(testDir, { recursive: true });
});

afterEach(() => {
  if (existsSync(testDir)) {
    rmSync(testDir, { recursive: true, force: true });
  }
});

function writeConfig(dir, content) {
  const path = join(dir, "nyolo.config.js");
  writeFileSync(path, content);
  return path;
}

// --- No configs → defaults ---

describe("resolveConfig — no configs", () => {
  test("returns recommended defaults when no config files exist", async () => {
    const rules = await resolveConfig(testDir, noGlobal);
    expect(rules.length).toBe(34);
    expect(rules[0].name).toBe("no-rm-rf-root");
  });
});

// --- Project config only (no global) → project rules + defaults ---

describe("resolveConfig — project config only", () => {
  test("prepends project rules before auto-appended defaults", async () => {
    writeConfig(testDir, `
      export default [
        { name: "proj-deny", tool: "Bash", match: { command: "*echo*" }, action: "deny", reason: "no echo" },
      ];
    `);
    const rules = await resolveConfig(testDir, noGlobal);
    expect(rules[0].name).toBe("proj-deny");
    // Defaults are auto-appended
    expect(rules.length).toBe(1 + 34);
    expect(rules[1].name).toBe("no-rm-rf-root");
  });

  test("project allow rules override auto-appended defaults", async () => {
    writeConfig(testDir, `
      export default [
        { name: "allow-aws", tool: "Bash", match: { command: { pattern: "\\\\baws\\\\s", parser: "regex" } }, action: "allow", reason: "aws ok here" },
      ];
    `);
    const rules = await resolveConfig(testDir, noGlobal);
    const result = evaluate("Bash", { command: "aws s3 ls" }, rules);
    expect(result.decision).toBe("allow");
    expect(result.rule).toBe("allow-aws");
  });

  test("project ask rules are preserved", async () => {
    writeConfig(testDir, `
      export default [
        { name: "proj-ask", tool: "Bash", match: { command: "*risky*" }, action: "ask", reason: "confirm" },
      ];
    `);
    const rules = await resolveConfig(testDir, noGlobal);
    expect(rules.some(r => r.name === "proj-ask")).toBe(true);
  });

  test("noDefaults suppresses auto-appended defaults", async () => {
    writeConfig(testDir, `
      export const noDefaults = true;
      export default [
        { name: "only-rule", tool: "Bash", match: { command: "*test*" }, action: "deny", reason: "only this" },
      ];
    `);
    const rules = await resolveConfig(testDir, noGlobal);
    expect(rules.length).toBe(1);
    expect(rules[0].name).toBe("only-rule");
  });

  test("noDefaults = false still includes defaults", async () => {
    writeConfig(testDir, `
      export const noDefaults = false;
      export default [
        { name: "proj-rule", tool: "Bash", match: { command: "*test*" }, action: "deny", reason: "test" },
      ];
    `);
    const rules = await resolveConfig(testDir, noGlobal);
    expect(rules.length).toBe(1 + 34);
  });
});

// --- Global config only → global rules as base (no defaults auto-appended) ---

describe("resolveConfig — global config only", () => {
  test("uses global rules as the complete base", async () => {
    const globalDir = join(testDir, "global");
    mkdirSync(globalDir, { recursive: true });
    const globalPath = join(globalDir, "nyolo.config.js");
    writeFileSync(globalPath, `
      export default [
        { name: "global-deny", tool: "Bash", match: { command: "*danger*" }, action: "deny", reason: "global denies" },
      ];
    `);
    const rules = await resolveConfig(testDir, { globalConfigPath: globalPath });
    // Global config IS the base — no defaults auto-appended
    expect(rules.length).toBe(1);
    expect(rules[0].name).toBe("global-deny");
  });
});

// --- Both configs → project prepended before global base ---

describe("resolveConfig — project + global", () => {
  test("merges project rules before global base", async () => {
    const globalDir = join(testDir, "global");
    mkdirSync(globalDir, { recursive: true });
    const globalPath = join(globalDir, "nyolo.config.js");
    writeFileSync(globalPath, `
      export default [
        { name: "global-rule", tool: "Bash", match: { command: "*global*" }, action: "deny", reason: "global" },
      ];
    `);
    writeConfig(testDir, `
      export default [
        { name: "project-rule", tool: "Bash", match: { command: "*project*" }, action: "deny", reason: "project" },
      ];
    `);
    const rules = await resolveConfig(testDir, { globalConfigPath: globalPath });
    expect(rules[0].name).toBe("project-rule");
    expect(rules[1].name).toBe("global-rule");
    expect(rules.length).toBe(2);
  });

  test("project allow rule overrides global deny (first-match-wins)", async () => {
    const globalDir = join(testDir, "global");
    mkdirSync(globalDir, { recursive: true });
    const globalPath = join(globalDir, "nyolo.config.js");
    writeFileSync(globalPath, `
      export default [
        { name: "global-deny", tool: "Bash", match: { command: "*safe*" }, action: "deny", reason: "global denies" },
      ];
    `);
    writeConfig(testDir, `
      export default [
        { name: "proj-allow", tool: "Bash", match: { command: "*safe*" }, action: "allow", reason: "project allows" },
      ];
    `);
    const rules = await resolveConfig(testDir, { globalConfigPath: globalPath });
    const result = evaluate("Bash", { command: "safe command" }, rules);
    expect(result.decision).toBe("allow");
    expect(result.rule).toBe("proj-allow");
  });
});

// --- Error handling ---

describe("resolveConfig — error handling", () => {
  test("handles malformed config gracefully (returns defaults)", async () => {
    writeConfig(testDir, `export default "not an array";`);
    const rules = await resolveConfig(testDir, noGlobal);
    expect(rules.length).toBe(34);
  });

  test("handles syntax error in config gracefully", async () => {
    writeConfig(testDir, `export default [[[broken`);
    const rules = await resolveConfig(testDir, noGlobal);
    expect(rules.length).toBe(34);
  });
});

// --- Edge cases ---

describe("resolveConfig — edge cases", () => {
  test("handles null cwd", async () => {
    const rules = await resolveConfig(null, noGlobal);
    expect(rules.length).toBe(34);
  });

  test("handles nonexistent cwd directory", async () => {
    const rules = await resolveConfig("/nonexistent/path/to/nowhere", noGlobal);
    expect(rules.length).toBe(34);
  });

  test("empty project config with no global gets defaults", async () => {
    writeConfig(testDir, `export default [];`);
    const rules = await resolveConfig(testDir, noGlobal);
    expect(rules.length).toBe(34);
  });

  test("empty project config with noDefaults gets empty", async () => {
    writeConfig(testDir, `
      export const noDefaults = true;
      export default [];
    `);
    const rules = await resolveConfig(testDir, noGlobal);
    expect(rules).toEqual([]);
  });
});
