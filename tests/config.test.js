import { describe, test, expect } from "bun:test";
import { stripJsonComments } from "../src/config.js";

// Helper: strip comments then parse as JSON
function parseJsonc(text) {
  return JSON.parse(stripJsonComments(text));
}

describe("stripJsonComments", () => {
  // --- Single-line comments ---

  test("strips single-line comment on its own line", () => {
    const input = '{\n// this is a comment\n"key": "value"\n}';
    expect(parseJsonc(input)).toEqual({ key: "value" });
  });

  test("strips single-line comment at end of line", () => {
    const input = '{"key": "value" // inline comment\n}';
    expect(parseJsonc(input)).toEqual({ key: "value" });
  });

  test("strips multiple single-line comments", () => {
    const input = '{\n// first\n"a": 1,\n// second\n"b": 2\n}';
    expect(parseJsonc(input)).toEqual({ a: 1, b: 2 });
  });

  // --- Multi-line comments ---

  test("strips multi-line comment", () => {
    const input = '{\n/* comment */\n"key": "value"\n}';
    expect(parseJsonc(input)).toEqual({ key: "value" });
  });

  test("strips multi-line comment spanning multiple lines", () => {
    const input = '{\n/*\n  multi\n  line\n*/\n"key": "value"\n}';
    expect(parseJsonc(input)).toEqual({ key: "value" });
  });

  test("strips inline multi-line comment", () => {
    const input = '{"key": /* comment */ "value"}';
    expect(parseJsonc(input)).toEqual({ key: "value" });
  });

  // --- Preserves strings containing comment-like content ---

  test("preserves // inside a string", () => {
    const input = '{"url": "https://example.com"}';
    expect(parseJsonc(input)).toEqual({ url: "https://example.com" });
  });

  test("preserves /* inside a string", () => {
    const input = '{"code": "a /* b */ c"}';
    expect(parseJsonc(input)).toEqual({ code: "a /* b */ c" });
  });

  test("preserves // inside a string with other real comments stripped", () => {
    const input = '{\n// real comment\n"url": "https://example.com/path"\n}';
    expect(parseJsonc(input)).toEqual({ url: "https://example.com/path" });
  });

  // --- Escaped quotes inside strings ---

  test("handles escaped quotes inside strings", () => {
    const input = '{"msg": "say \\"hello\\""}';
    expect(parseJsonc(input)).toEqual({ msg: 'say "hello"' });
  });

  test("handles escaped quote before // that is still inside a string", () => {
    // The \" does not end the string, so the // is still inside the string
    const input = '{"val": "test \\"// not a comment\\" end"}';
    expect(parseJsonc(input)).toEqual({ val: 'test "// not a comment" end' });
  });

  test("handles escaped backslash before closing quote", () => {
    // \\\\ at end of string = literal backslash, then " closes the string
    const input = '{"path": "C:\\\\"}';
    expect(parseJsonc(input)).toEqual({ path: "C:\\" });
  });

  // --- Edge cases ---

  test("handles empty input", () => {
    expect(stripJsonComments("")).toBe("");
  });

  test("handles input with no comments", () => {
    const input = '{"key": "value"}';
    expect(stripJsonComments(input)).toBe(input);
  });

  test("handles comment-only input", () => {
    const result = stripJsonComments("// just a comment");
    expect(result.trim()).toBe("");
  });

  test("handles unterminated multi-line comment (no closing */)", () => {
    // Should strip from /* to end of input without crashing
    const input = '{"a": 1} /* never closed';
    const result = stripJsonComments(input);
    expect(result).toContain('"a": 1');
    // The unclosed comment content should be stripped
    expect(result).not.toContain("never closed");
  });

  test("handles adjacent comments", () => {
    const input = '{\n// one\n// two\n"key": "value"\n}';
    expect(parseJsonc(input)).toEqual({ key: "value" });
  });

  test("handles comment immediately after string", () => {
    const input = '{"key": "value"/* comment */}';
    expect(parseJsonc(input)).toEqual({ key: "value" });
  });

  // --- Regression: the actual example config should parse ---

  test("parses a realistic JSONC config", () => {
    const input = `{
  // Custom rules (evaluated before defaults, first-match-wins)
  "rules": [
    // Example: allow terraform plan
    // {
    //   "name": "allow-terraform-plan",
    //   "tool": "Bash",
    //   "match": { "command": "^terraform\\\\s+plan\\\\b" },
    //   "action": "allow",
    //   "reason": "terraform plan is read-only"
    // }
  ],

  /* Disable specific default rules by name */
  "disableDefaults": [],

  // Logging: "debug" | "info" | "warn" | "error" | "silent"
  "logLevel": "warn",

  /* Optional: write logs to a file */
  "logFile": null
}`;
    const result = parseJsonc(input);
    expect(result.rules).toEqual([]);
    expect(result.disableDefaults).toEqual([]);
    expect(result.logLevel).toBe("warn");
    expect(result.logFile).toBeNull();
  });

  // --- Regex patterns in JSON strings (critical for this project) ---

  test("preserves backslash-heavy regex patterns in strings", () => {
    // This is the kind of pattern our rules use — must survive comment stripping
    const input = '{"match": {"command": "\\\\brm\\\\s+(-[a-zA-Z]*r)\\\\s+\\\\/"}}';
    const result = parseJsonc(input);
    expect(result.match.command).toBe("\\brm\\s+(-[a-zA-Z]*r)\\s+\\/");
  });
});
