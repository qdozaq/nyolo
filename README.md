# nyolo

Run Claude Code using `--dangerously-skip-permissions` — with safety guardrails.

**nyolo** is a `PreToolUse` hook for Claude Code that automatically blocks or requires confirmation for dangerous operations: recursive deletes, cloud CLI mutations, force pushes, sudo, and more.

## Requirements

- [Bun](https://bun.sh) v1.0+

## Quick start

```bash
# One-liner (requires bun)
npx nyolo install
```

That's it. The install command registers the hook in `~/.claude/settings.json` with a direct path to the binary.

## What gets blocked

| Category | Examples | Action |
|---|---|---|
| Filesystem | `rm -rf /`, `rm -rf ~`, `rm -rf .` | deny |
| System | `sudo`, `shutdown`, `mkfs`, `dd if=…` | deny |
| Database | `DROP TABLE`, `TRUNCATE` | deny |
| Container | `kubectl delete namespace` | deny |
| Git | `git push --force`, `git reset --hard`, `git clean -f` | ask |
| Cloud | `aws`, `gcloud`, `az`, `terraform apply/destroy` | ask |
| Network | `curl … \| bash`, `npm publish`, `gem push` | ask |
| Sensitive files | `.env`, `.ssh/` | ask |
| Warnings | `kill -9`, `git branch -D`, `git stash drop` | ask |

**deny** = blocked outright. **ask** = Claude must get explicit approval before proceeding.

Rules are evaluated against each sub-command in a pipeline (e.g. `echo ok; rm -rf /` is caught via the `rm -rf /` segment).

## Install / Uninstall

```bash
# Install hook into ~/.claude/settings.json
npx nyolo install

# Remove the hook
npx nyolo uninstall
```

## Commands

```bash
nyolo install    # add hook to ~/.claude/settings.json
nyolo uninstall  # remove hook from ~/.claude/settings.json
nyolo rules      # list all active rules with their actions
```

Running with no subcommand (or piped from Claude Code) operates in hook mode: reads a JSON event from stdin and writes the permission decision to stdout.

## Customizing rules

nyolo uses an ESLint-style flat config: a `nyolo.config.js` file that exports an array of rules.

### Project config (no install needed)

Drop a `nyolo.config.js` in your project root. No imports required — the 35 recommended defaults are auto-appended after your rules:

```js
// <project>/nyolo.config.js
export default [
  {
    name: "allow-terraform-plan",
    tool: "Bash",
    match: { command: "terraform plan*" },
    action: "allow",
    reason: "terraform plan is read-only",
  },
];
// Defaults are auto-appended after these rules (first-match-wins).
```

To use **only** your rules with no defaults:

```js
export const noDefaults = true;
export default [
  // your rules here — no defaults appended
];
```

### Global config (composed via imports)

Create `~/.claude/nyolo.config.js` for rules that apply to all projects. The global config **is** the base rule set — install nyolo globally to use imports:

```js
// ~/.claude/nyolo.config.js
import { recommended } from "nyolo";

export default [
  {
    name: "allow-aws-s3-ls",
    tool: "Bash",
    match: { command: "aws s3 ls*" },
    action: "allow",
    reason: "listing is read-only",
  },
  ...recommended,
];
```

Or pick specific categories:

```js
import { filesystem, git, network } from "nyolo";

export default [...filesystem, ...git, ...network];
```

### How configs merge

| Scenario | Result |
|---|---|
| No configs | All 35 recommended defaults |
| Project only | `[...projectRules, ...recommended]` |
| Global only | `[...globalRules]` (global IS the base) |
| Both | `[...projectRules, ...globalRules]` |

Project rules are always evaluated first (first-match-wins), so a project `allow` rule overrides a global `deny` for the same pattern.

### Available category exports

```js
import {
  recommended,  // all 35 defaults
  filesystem,   // rm -rf /, ~, .
  cloud,        // aws, gcloud, az, terraform, kubectl, helm, pulumi
  network,      // curl|bash, npm publish, web fetch
  git,          // force push, reset --hard, clean -f
  database,     // DROP TABLE, TRUNCATE
  system,       // sudo, shutdown, mkfs, chmod 777
  container,    // docker prune, kubectl delete namespace
  protection,   // editing nyolo/claude settings files
  sensitive,    // .env, .ssh
  warnings,     // kill -9, git branch -D, git stash drop
  defineConfig, // identity fn for editor autocomplete
} from "nyolo";
```

## Rule format

```js
{
  name: "my-rule",          // unique name
  tool: "Bash|Write|Edit",  // pipe-delimited tool filter (omit for any tool)
  match: {
    // field name → glob pattern (default) or regex object
    command: "*dangerous*",
    file_path: { pattern: "\\.env$", parser: "regex" },
  },
  action: "deny",           // "deny" | "ask" | "allow"
  reason: "Explanation shown to Claude",
}
```

Glob patterns use [micromatch](https://github.com/micromatch/micromatch) with extglob support. On `command` fields, `*` matches `/` (relaxed path semantics).

## Callback rules

A rule can also be a plain function for cases where declarative matching isn't expressive enough:

```js
// nyolo.config.js
export default [
  // Callback rule: receives (toolName, toolInput, { cwd }), returns { action, reason } or null
  (toolName, toolInput, { cwd }) => {
    if (toolName === "Bash" && /secret/.test(toolInput.command)) {
      return { action: "deny", reason: "Commands containing 'secret' are not allowed" };
    }
    return null; // null or undefined = skip, continue to next rule
  },

  // Declarative rules can follow — first-match-wins is preserved
  {
    name: "allow-ls",
    tool: "Bash",
    match: { command: "ls*" },
    action: "allow",
    reason: "read-only listing",
  },
];
```

**Callback signature**: `(toolName: string, toolInput: object, context: { cwd: string }) => { action, reason } | null | undefined`

- Return `{ action: "allow" | "deny" | "ask", reason: string }` to make a decision.
- Return `null` or `undefined` to skip (next rule is evaluated).
- If the callback throws, evaluation stops and the decision is **deny** with the error message as reason. This is intentional — a thrown error likely means broken safety logic, and failing closed is safer.
- Async callbacks (returning a Promise) are not supported and will be denied immediately.

## Skills

nyolo includes a skill for writing new permission rules. Install it with [skills](https://github.com/vercel-labs/skills):

```bash
npx skills add https://github.com/qdozaq/nyolo.git
```

### nyolo-write-rule

Interactively creates a new nyolo permission rule. It will:

1. Ask what you want to match (command, file path, URL, etc.)
2. Ask whether to save the rule at **project** level (`./nyolo.config.js`) or **global** level (`~/.claude/nyolo.config.js`)
3. Write the rule in the correct format with proper pattern syntax

## Build standalone binary

```bash
bun run build              # current platform
bun run build:darwin-arm64 # macOS Apple Silicon
bun run build:linux-x64    # Linux x86_64
```

## License

MIT
