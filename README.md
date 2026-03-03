# nyolo

Run Claude Code autonomously — with safety guardrails.

**nyolo** is a `PreToolUse` hook for Claude Code that automatically blocks or requires confirmation for dangerous operations: recursive deletes, cloud CLI mutations, force pushes, sudo, and more.

## Requirements

- [Bun](https://bun.sh) v1.0+

## Quick start

```bash
# One-liner (requires bun)
npx nyolo install
```

That's it. The install command registers the hook in `~/.claude/settings.json` with a direct path to the binary — no npx overhead on each tool call.

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
nyolo test       # run quick self-test against active rules
nyolo rules      # list all active rules with their actions
```

Running with no subcommand (or piped from Claude Code) operates in hook mode: reads a JSON event from stdin and writes the permission decision to stdout.

## Customizing rules

Create `~/.claude/permissions.json` to configure global behaviour:

```jsonc
{
  // Prepend custom rules (first-match-wins)
  "rules": [
    {
      "name": "allow-aws-s3-ls",
      "tool": "Bash",
      "match": { "command": "aws s3 ls*" },
      "action": "allow",
      "reason": "listing is read-only"
    }
  ],

  // Disable specific built-in rules by name
  "disableDefaults": [],

  // Set to false to use only your own rules
  "useDefaults": true,

  // Logging: "debug" | "info" | "warn" | "error" | "silent"
  "logLevel": "warn",

  // Optional: write logs to a file
  "logFile": null
}
```

For project-scoped rules, create `.claude-permissions.json` in your repo root. Project rules are **additive-only** (deny/ask only, no allow overrides) unless you set `"allowProjectOverrides": true` in your global config.

## Rule format

```jsonc
{
  "name": "my-rule",          // unique name
  "tool": "Bash|Write|Edit",  // pipe-delimited tool filter (omit for any tool)
  "match": {
    // field name → glob pattern (default) or regex object
    "command": "*dangerous*",
    "file_path": { "pattern": "\\.env$", "parser": "regex" }
  },
  "action": "deny" | "ask" | "allow",
  "reason": "Explanation shown to Claude"
}
```

Glob patterns use [micromatch](https://github.com/micromatch/micromatch) with extglob support. On `command` fields, `*` matches `/` (relaxed path semantics).

## Build standalone binary

```bash
bun run build              # current platform
bun run build:darwin-arm64 # macOS Apple Silicon
bun run build:linux-x64    # Linux x86_64
```

## License

MIT
