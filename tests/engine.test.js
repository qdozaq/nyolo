import { describe, test, expect } from "bun:test";
import { evaluate, splitSubCommands } from "../src/engine.js";

describe("evaluate", () => {
  test("returns allow when no rules match", () => {
    const result = evaluate("Bash", { command: "ls -la" }, []);
    expect(result.decision).toBe("allow");
  });

  test("returns allow when rules array is empty", () => {
    const result = evaluate("Bash", { command: "dangerous" }, []);
    expect(result.decision).toBe("allow");
    expect(result.rule).toBeUndefined();
  });

  test("returns deny when a deny rule matches", () => {
    const rules = [{
      name: "test-deny",
      tool: "Bash",
      match: (input) => input.command.includes("dangerous"),
      action: "deny",
      reason: "test reason",
    }];
    const result = evaluate("Bash", { command: "dangerous command" }, rules);
    expect(result.decision).toBe("deny");
    expect(result.rule).toBe("test-deny");
    expect(result.reason).toBe("test reason");
  });

  test("returns ask when an ask rule matches", () => {
    const rules = [{
      name: "test-ask",
      tool: "Bash",
      match: (input) => input.command.includes("risky"),
      action: "ask",
      reason: "confirm this",
    }];
    const result = evaluate("Bash", { command: "risky command" }, rules);
    expect(result.decision).toBe("ask");
    expect(result.rule).toBe("test-ask");
  });

  test("returns allow when an allow rule matches", () => {
    const rules = [{
      name: "test-allow",
      tool: "Bash",
      match: (input) => input.command.includes("safe"),
      action: "allow",
      reason: "explicitly allowed",
    }];
    const result = evaluate("Bash", { command: "safe command" }, rules);
    expect(result.decision).toBe("allow");
    expect(result.rule).toBe("test-allow");
  });

  test("skips rules for non-matching tools", () => {
    const rules = [{
      name: "bash-only",
      tool: "Bash",
      match: () => true,
      action: "deny",
      reason: "bash only",
    }];
    const result = evaluate("Write", { file_path: "/tmp/test" }, rules);
    expect(result.decision).toBe("allow");
  });

  test("matches rules with no tool filter against any tool", () => {
    const rules = [{
      name: "catch-all",
      match: () => true,
      action: "deny",
      reason: "blocks everything",
    }];
    expect(evaluate("Bash", { command: "ls" }, rules).decision).toBe("deny");
    expect(evaluate("Write", { file_path: "/tmp/x" }, rules).decision).toBe("deny");
    expect(evaluate("Edit", { file_path: "/tmp/x" }, rules).decision).toBe("deny");
    expect(evaluate("Read", { file_path: "/tmp/x" }, rules).decision).toBe("deny");
  });

  test("first matching rule wins", () => {
    const rules = [
      { name: "allow-first", tool: "Bash", match: () => true, action: "allow", reason: "first" },
      { name: "deny-second", tool: "Bash", match: () => true, action: "deny", reason: "second" },
    ];
    const result = evaluate("Bash", { command: "anything" }, rules);
    expect(result.decision).toBe("allow");
    expect(result.rule).toBe("allow-first");
  });

  test("skips non-matching rules and picks the first match", () => {
    const rules = [
      { name: "no-match", tool: "Bash", match: () => false, action: "deny", reason: "nope" },
      { name: "yes-match", tool: "Bash", match: () => true, action: "deny", reason: "this one" },
    ];
    const result = evaluate("Bash", { command: "anything" }, rules);
    expect(result.rule).toBe("yes-match");
  });

  test("supports pipe-delimited tool matching (Write|Edit)", () => {
    const rules = [{
      name: "write-tools",
      tool: "Write|Edit",
      match: () => true,
      action: "deny",
      reason: "no writing",
    }];
    expect(evaluate("Write", { file_path: "/tmp/x" }, rules).decision).toBe("deny");
    expect(evaluate("Edit", { file_path: "/tmp/x" }, rules).decision).toBe("deny");
    expect(evaluate("Read", { file_path: "/tmp/x" }, rules).decision).toBe("allow");
    expect(evaluate("Bash", { command: "ls" }, rules).decision).toBe("allow");
  });

  test("supports RegExp tool filter", () => {
    const rules = [{
      name: "regex-tool",
      tool: /^(Write|Edit)$/,
      match: () => true,
      action: "deny",
      reason: "no writing",
    }];
    expect(evaluate("Write", { file_path: "/tmp/x" }, rules).decision).toBe("deny");
    expect(evaluate("Edit", { file_path: "/tmp/x" }, rules).decision).toBe("deny");
    expect(evaluate("Bash", { command: "ls" }, rules).decision).toBe("allow");
  });

  test("fails open if match function throws", () => {
    const rules = [{
      name: "broken",
      tool: "Bash",
      match: () => { throw new Error("bug"); },
      action: "deny",
      reason: "broken",
    }];
    const result = evaluate("Bash", { command: "ls" }, rules);
    expect(result.decision).toBe("allow");
  });

  test("continues to next rule after a throwing rule", () => {
    const rules = [
      {
        name: "broken",
        tool: "Bash",
        match: () => { throw new Error("bug"); },
        action: "deny",
        reason: "broken",
      },
      {
        name: "good-rule",
        tool: "Bash",
        match: () => true,
        action: "deny",
        reason: "caught by second",
      },
    ];
    const result = evaluate("Bash", { command: "ls" }, rules);
    expect(result.decision).toBe("deny");
    expect(result.rule).toBe("good-rule");
  });

  test("invalid regex in tool field does not crash engine or skip remaining rules", () => {
    const rules = [
      {
        name: "bad-regex",
        tool: "[invalid(",
        match: () => true,
        action: "deny",
        reason: "bad regex",
      },
      {
        name: "valid-rule",
        tool: "Bash",
        match: () => true,
        action: "deny",
        reason: "this should still fire",
      },
    ];
    const result = evaluate("Bash", { command: "ls" }, rules);
    expect(result.decision).toBe("deny");
    expect(result.rule).toBe("valid-rule");
  });
});

// --- Declarative Rule Evaluation ---

describe("evaluate — declarative match objects", () => {
  test("matches a simple string pattern against input field (regex)", () => {
    const rules = [{
      name: "no-echo",
      tool: "Bash",
      match: { command: { "pattern": "\\becho\\b", "parser": "regex" } },
      action: "deny",
      reason: "no echo",
    }];
    expect(evaluate("Bash", { command: "echo hello" }, rules).decision).toBe("deny");
    expect(evaluate("Bash", { command: "ls -la" }, rules).decision).toBe("allow");
  });

  test("matches file_path field for Write/Edit tools (regex)", () => {
    const rules = [{
      name: "no-env",
      tool: "Write|Edit",
      match: { file_path: { "pattern": "\\.env($|\\.)", "parser": "regex" } },
      action: "deny",
      reason: "no env files",
    }];
    expect(evaluate("Write", { file_path: "/project/.env" }, rules).decision).toBe("deny");
    expect(evaluate("Edit", { file_path: "/project/.env.local" }, rules).decision).toBe("deny");
    expect(evaluate("Write", { file_path: "/project/src/app.js" }, rules).decision).toBe("allow");
  });

  test("supports MatchPattern object with flags (case-insensitive, regex)", () => {
    const rules = [{
      name: "no-drop",
      tool: "Bash",
      match: { command: { pattern: "\\bDROP\\s+TABLE\\b", parser: "regex", flags: "i" } },
      action: "deny",
      reason: "no drop",
    }];
    expect(evaluate("Bash", { command: "DROP TABLE users" }, rules).decision).toBe("deny");
    expect(evaluate("Bash", { command: "drop table users" }, rules).decision).toBe("deny");
    expect(evaluate("Bash", { command: "SELECT * FROM users" }, rules).decision).toBe("allow");
  });

  test("AND logic: all fields must match", () => {
    const rules = [{
      name: "multi-field",
      tool: "Bash",
      match: { command: "*curl*", description: "*download*" },
      action: "deny",
      reason: "both must match",
    }];
    expect(evaluate("Bash", { command: "curl http://x", description: "download file" }, rules).decision).toBe("deny");
    expect(evaluate("Bash", { command: "curl http://x", description: "upload file" }, rules).decision).toBe("allow");
    expect(evaluate("Bash", { command: "wget http://x", description: "download file" }, rules).decision).toBe("allow");
  });

  test("returns false when matched field is not a string", () => {
    const rules = [{
      name: "needs-string",
      tool: "Bash",
      match: { command: "*echo*" },
      action: "deny",
      reason: "test",
    }];
    expect(evaluate("Bash", { command: 123 }, rules).decision).toBe("allow");
    expect(evaluate("Bash", { command: null }, rules).decision).toBe("allow");
    expect(evaluate("Bash", {}, rules).decision).toBe("allow");
  });

  test("returns false when matched field is missing from input", () => {
    const rules = [{
      name: "needs-field",
      tool: "Bash",
      match: { nonexistent: "*pattern*" },
      action: "deny",
      reason: "test",
    }];
    expect(evaluate("Bash", { command: "ls" }, rules).decision).toBe("allow");
  });

  test("first-match-wins with declarative rules", () => {
    const rules = [
      { name: "allow-ls", tool: "Bash", match: { command: "*ls*" }, action: "allow", reason: "safe" },
      { name: "deny-all", tool: "Bash", match: { command: "*" }, action: "deny", reason: "catch-all" },
    ];
    expect(evaluate("Bash", { command: "ls -la" }, rules).decision).toBe("allow");
    expect(evaluate("Bash", { command: "ls -la" }, rules).rule).toBe("allow-ls");
    expect(evaluate("Bash", { command: "rm -rf /" }, rules).decision).toBe("deny");
    expect(evaluate("Bash", { command: "rm -rf /" }, rules).rule).toBe("deny-all");
  });

  test("no tool filter matches any tool (declarative)", () => {
    const rules = [{
      name: "catch-all",
      match: { command: "*dangerous*" },
      action: "deny",
      reason: "blocks everywhere",
    }];
    expect(evaluate("Bash", { command: "dangerous" }, rules).decision).toBe("deny");
    expect(evaluate("CustomTool", { command: "dangerous" }, rules).decision).toBe("deny");
  });

  test("invalid regex in match pattern fails open and skips to next rule", () => {
    const rules = [
      { name: "bad-pattern", tool: "Bash", match: { command: { pattern: "[invalid(", parser: "regex" } }, action: "deny", reason: "bad" },
      { name: "good-rule", tool: "Bash", match: { command: "*echo*" }, action: "deny", reason: "good" },
    ];
    const result = evaluate("Bash", { command: "echo hello" }, rules);
    expect(result.decision).toBe("deny");
    expect(result.rule).toBe("good-rule");
  });

  test("empty match object matches everything (vacuously true)", () => {
    const rules = [{
      name: "empty-match",
      tool: "Bash",
      match: {},
      action: "deny",
      reason: "catches all",
    }];
    expect(evaluate("Bash", { command: "anything" }, rules).decision).toBe("deny");
  });

  test("mixed declarative and legacy function rules coexist", () => {
    const rules = [
      { name: "legacy", tool: "Bash", match: (input) => input.command === "legacy", action: "deny", reason: "legacy" },
      { name: "declarative", tool: "Bash", match: { command: "declarative" }, action: "deny", reason: "declarative" },
    ];
    expect(evaluate("Bash", { command: "legacy" }, rules).rule).toBe("legacy");
    expect(evaluate("Bash", { command: "declarative" }, rules).rule).toBe("declarative");
    expect(evaluate("Bash", { command: "neither" }, rules).decision).toBe("allow");
  });
});

// --- splitSubCommands ---

describe("splitSubCommands", () => {
  // -- basic splitting --
  test("semicolon: splits into two segments", () => {
    expect(splitSubCommands("cmd1; cmd2")).toEqual(["cmd1", "cmd2"]);
  });

  test("&&: splits into two segments", () => {
    expect(splitSubCommands("cmd1 && cmd2")).toEqual(["cmd1", "cmd2"]);
  });

  test("||: splits into two segments", () => {
    expect(splitSubCommands("cmd1 || cmd2")).toEqual(["cmd1", "cmd2"]);
  });

  test("mixed &&/||: splits into three segments", () => {
    const result = splitSubCommands("cmd1 && cmd2 || cmd3");
    expect(result).toEqual(["cmd1", "cmd2", "cmd3"]);
  });

  // -- control structure keywords --
  test("for loop: extracts body command", () => {
    const result = splitSubCommands("for i in 1 2; do echo $i; done");
    expect(result.some(s => s.includes("echo"))).toBe(true);
  });

  test("while loop: extracts body command", () => {
    const result = splitSubCommands("while true; do ls; done");
    expect(result.some(s => s.includes("ls"))).toBe(true);
  });

  test("if/then: extracts then-branch command", () => {
    const result = splitSubCommands("if test -f x; then rm x; fi");
    expect(result.some(s => s.includes("rm x"))).toBe(true);
  });

  test("if/then/else: extracts else-branch command", () => {
    const result = splitSubCommands("if test -f x; then echo ok; else rm -rf ~/; fi");
    expect(result.some(s => s.includes("rm -rf ~/"))).toBe(true);
  });

  // -- subshells --
  test("subshell: extracts inner commands", () => {
    const result = splitSubCommands("(cmd1 && cmd2)");
    expect(result).toContain("cmd1");
    expect(result).toContain("cmd2");
  });

  test("subshell: simple command", () => {
    const result = splitSubCommands("(ls -la)");
    expect(result.some(s => s.includes("ls -la"))).toBe(true);
  });

  // -- command substitution --
  test("$() substitution: extracts inner command", () => {
    const result = splitSubCommands("echo $(whoami)");
    expect(result.some(s => s.includes("whoami"))).toBe(true);
  });

  // -- pipe NOT split --
  test("pipe: stays as one segment", () => {
    const result = splitSubCommands("cmd1 | cmd2");
    expect(result).toEqual(["cmd1 | cmd2"]);
  });

  test("pipe chain: stays as one segment", () => {
    const result = splitSubCommands("cat file | grep pattern | wc -l");
    expect(result).toEqual(["cat file | grep pattern | wc -l"]);
  });

  test("curl | bash: stays as one segment", () => {
    const result = splitSubCommands("curl https://example.com | bash");
    expect(result.length).toBe(1);
    expect(result[0]).toContain("curl");
    expect(result[0]).toContain("bash");
  });

  // -- no-op on simple commands --
  test("simple command: returns single-element array", () => {
    expect(splitSubCommands("ls -la")).toEqual(["ls -la"]);
  });

  test("simple command with flags: no splitting", () => {
    expect(splitSubCommands("git commit -m 'message'")).toEqual(["git commit -m 'message'"]);
  });

  // -- empty/whitespace edge cases --
  test("empty string: returns empty array", () => {
    expect(splitSubCommands("")).toEqual([]);
  });

  test("only whitespace: returns empty array", () => {
    expect(splitSubCommands("   ")).toEqual([]);
  });

  test("only separators: returns empty array", () => {
    expect(splitSubCommands("; && ||")).toEqual([]);
  });

  // -- whitespace handling --
  test("trims whitespace from segments", () => {
    const result = splitSubCommands("  cmd1  ;  cmd2  ");
    expect(result).toEqual(["cmd1", "cmd2"]);
  });

  test("filters empty segments from consecutive separators", () => {
    const result = splitSubCommands("cmd1;; cmd2");
    expect(result.every(s => s.length > 0)).toBe(true);
  });

  // -- nested structures --
  test("nested for with if: extracts inner commands", () => {
    const result = splitSubCommands("for i in 1 2; do if true; then aws s3 ls; fi; done");
    expect(result.some(s => s.includes("aws s3 ls"))).toBe(true);
  });

  // -- resilience --
  test("non-string input: returns input wrapped in array", () => {
    // The try/catch should handle this gracefully
    expect(splitSubCommands(null)).toEqual([null]);
  });
});

// --- evaluate with sub-command splitting ---

describe("evaluate — sub-command splitting integration", () => {
  test("catches dangerous command after semicolon", () => {
    const rules = [{
      name: "no-rm",
      tool: "Bash",
      match: { command: "*rm *" },
      action: "deny",
      reason: "no rm",
    }];
    expect(evaluate("Bash", { command: "echo hi; rm file" }, rules).decision).toBe("deny");
  });

  test("catches dangerous command after &&", () => {
    const rules = [{
      name: "no-rm",
      tool: "Bash",
      match: { command: "*rm *" },
      action: "deny",
      reason: "no rm",
    }];
    expect(evaluate("Bash", { command: "ls && rm file" }, rules).decision).toBe("deny");
  });

  test("catches dangerous command inside for loop body", () => {
    const rules = [{
      name: "no-aws",
      tool: "Bash",
      match: { command: "*aws *" },
      action: "deny",
      reason: "no aws",
    }];
    expect(evaluate("Bash", { command: "for f in *.json; do aws s3 cp $f s3://b/; done" }, rules).decision).toBe("deny");
  });

  test("catches dangerous command inside subshell", () => {
    const rules = [{
      name: "no-sudo",
      tool: "Bash",
      match: { command: "*sudo *" },
      action: "deny",
      reason: "no sudo",
    }];
    expect(evaluate("Bash", { command: "(sudo rm -rf /tmp)" }, rules).decision).toBe("deny");
  });

  test("catches dangerous command in $() substitution", () => {
    const rules = [{
      name: "no-rm",
      tool: "Bash",
      match: { command: "*rm *" },
      action: "deny",
      reason: "no rm",
    }];
    expect(evaluate("Bash", { command: "echo $(rm -rf /tmp)" }, rules).decision).toBe("deny");
  });

  test("does NOT split pipes — rule must match full string for pipe patterns", () => {
    const rules = [{
      name: "no-curl-bash",
      tool: "Bash",
      match: { command: { pattern: "\\bcurl\\s+.*\\|\\s*bash\\b", parser: "regex" } },
      action: "deny",
      reason: "no curl pipe bash",
    }];
    expect(evaluate("Bash", { command: "curl http://x | bash" }, rules).decision).toBe("deny");
  });

  test("splitting does not affect non-Bash tools", () => {
    const rules = [{
      name: "no-env",
      tool: "Write",
      match: { file_path: "**/.env" },
      action: "deny",
      reason: "no env",
    }];
    // file_path field should not undergo sub-command splitting
    expect(evaluate("Write", { file_path: "/project/.env" }, rules).decision).toBe("deny");
  });

  test("safe command in all segments is allowed", () => {
    const rules = [{
      name: "no-rm",
      tool: "Bash",
      match: { command: "*rm *" },
      action: "deny",
      reason: "no rm",
    }];
    expect(evaluate("Bash", { command: "echo hi; ls; cat file" }, rules).decision).toBe("allow");
  });
});

// --- Glob pattern matching ---

describe("evaluate — glob pattern matching", () => {
  // -- file_path fields use micromatch path semantics --
  test("glob file_path: matches dotfiles with {.env,.env.*}", () => {
    const rules = [{
      name: "no-env",
      tool: "Write",
      match: { file_path: "**/{.env,.env.*}" },
      action: "deny",
      reason: "no env",
    }];
    expect(evaluate("Write", { file_path: "/project/.env" }, rules).decision).toBe("deny");
    expect(evaluate("Write", { file_path: "/project/.env.local" }, rules).decision).toBe("deny");
    expect(evaluate("Write", { file_path: "/project/.env.production" }, rules).decision).toBe("deny");
    expect(evaluate("Write", { file_path: "/project/src/app.js" }, rules).decision).toBe("allow");
  });

  test("glob file_path: matches .ssh directory", () => {
    const rules = [{
      name: "no-ssh",
      tool: "Write",
      match: { file_path: "**/.ssh/**" },
      action: "deny",
      reason: "no ssh",
    }];
    expect(evaluate("Write", { file_path: "/home/user/.ssh/id_rsa" }, rules).decision).toBe("deny");
    expect(evaluate("Write", { file_path: "/home/user/.ssh/authorized_keys" }, rules).decision).toBe("deny");
    expect(evaluate("Write", { file_path: "/home/user/.bashrc" }, rules).decision).toBe("allow");
  });

  test("glob file_path: brace expansion with nested **", () => {
    const rules = [{
      name: "no-hook",
      tool: "Write",
      match: { file_path: "**/nyolo/{hook.js,bin/**,src/**,config.js}" },
      action: "deny",
      reason: "no hook edit",
    }];
    expect(evaluate("Write", { file_path: "/x/nyolo/hook.js" }, rules).decision).toBe("deny");
    expect(evaluate("Write", { file_path: "/x/nyolo/src/engine.js" }, rules).decision).toBe("deny");
    expect(evaluate("Write", { file_path: "/x/nyolo/config.js" }, rules).decision).toBe("deny");
    expect(evaluate("Write", { file_path: "/x/nyolo/README.md" }, rules).decision).toBe("allow");
  });

  // -- command fields: * matches / (relaxed mode) --
  test("glob command: * matches strings containing /", () => {
    const rules = [{
      name: "no-sudo",
      tool: "Bash",
      match: { command: "*sudo *" },
      action: "deny",
      reason: "no sudo",
    }];
    expect(evaluate("Bash", { command: "sudo rm -rf /home/user" }, rules).decision).toBe("deny");
  });

  // -- extglob patterns --
  test("glob command: extglob @() alternation", () => {
    const rules = [{
      name: "no-helm",
      tool: "Bash",
      match: { command: "*helm @(install|upgrade)*" },
      action: "deny",
      reason: "no helm mutate",
    }];
    expect(evaluate("Bash", { command: "helm install chart" }, rules).decision).toBe("deny");
    expect(evaluate("Bash", { command: "helm upgrade my-release" }, rules).decision).toBe("deny");
    expect(evaluate("Bash", { command: "helm list" }, rules).decision).toBe("allow");
  });

  test("glob command: extglob ?() optional segment", () => {
    const rules = [{
      name: "no-chmod-777",
      tool: "Bash",
      match: { command: "*chmod ?(-R )777*" },
      action: "deny",
      reason: "no chmod 777",
    }];
    expect(evaluate("Bash", { command: "chmod 777 /var/www" }, rules).decision).toBe("deny");
    expect(evaluate("Bash", { command: "chmod -R 777 /var/www" }, rules).decision).toBe("deny");
    expect(evaluate("Bash", { command: "chmod 755 /var/www" }, rules).decision).toBe("allow");
  });

  // -- parser: "regex" override --
  test("parser: regex overrides default glob parsing", () => {
    const rules = [{
      name: "regex-rule",
      tool: "Bash",
      match: { command: { pattern: "\\becho\\b", parser: "regex" } },
      action: "deny",
      reason: "regex mode",
    }];
    expect(evaluate("Bash", { command: "echo hello" }, rules).decision).toBe("deny");
    expect(evaluate("Bash", { command: "ls -la" }, rules).decision).toBe("allow");
  });

  // -- simple glob strings default to glob parser --
  test("simple string patterns default to glob", () => {
    const rules = [{
      name: "no-docker-prune",
      tool: "Bash",
      match: { command: "*docker system prune*" },
      action: "deny",
      reason: "no prune",
    }];
    expect(evaluate("Bash", { command: "docker system prune" }, rules).decision).toBe("deny");
    expect(evaluate("Bash", { command: "docker system prune -a" }, rules).decision).toBe("deny");
    expect(evaluate("Bash", { command: "docker ps" }, rules).decision).toBe("allow");
  });
});
