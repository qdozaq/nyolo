# Contributing to nyolo

## Setup

```bash
git clone <repo>
cd nyolo
bun install
bun test
```

## Adding rules

Default rules live in `src/defaults.json`. Each rule is a JSON object:

```json
{
  "name": "unique-rule-name",
  "description": "What it does",
  "category": "filesystem|cloud|network|git|database|system|container|protection|sensitive|warnings",
  "tool": "Bash",
  "match": { "command": "*pattern*" },
  "action": "deny|ask|allow",
  "reason": "Message shown when rule triggers"
}
```

Add tests for any new rule in `tests/rules.test.js`.

## Tests

```bash
bun test                        # all tests
bun test tests/engine.test.js   # engine unit tests
bun test tests/rules.test.js    # default rule tests
bun test tests/config.test.js   # config parsing tests
```

## Rule evaluation order

1. Project deny/ask rules (from `.claude-permissions.json`)
2. Global custom rules (from `~/.claude/permissions.json`)
3. Default rules (`src/defaults.json`)

First match wins.

## Pull requests

- Keep changes focused. One logical change per PR.
- New default rules need a test.
- Do not change rule names of existing defaults (they're referenced by `disableDefaults`).
