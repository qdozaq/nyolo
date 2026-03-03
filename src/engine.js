import micromatch from "micromatch";

/**
 * @typedef {"allow" | "deny" | "ask"} PermissionAction
 *
 * @typedef {Object} MatchPattern
 * @property {string} pattern - Pattern string (glob or regex)
 * @property {"glob" | "regex"} [parser] - Parser type (default: "glob")
 * @property {string} [flags] - Regex flags (only meaningful when parser is "regex")
 *
 * @typedef {Object} DeclarativeRule
 * @property {string} name
 * @property {string} [description]
 * @property {string} [category]
 * @property {string} [tool] - Tool name filter (exact or pipe-delimited, e.g. "Bash" or "Write|Edit")
 * @property {Record<string, string | MatchPattern>} match - Map of input field to pattern (glob or regex)
 * @property {PermissionAction} action
 * @property {string} reason
 *
 * @typedef {Object} EvalResult
 * @property {PermissionAction} decision
 * @property {string} [rule] - Name of the matched rule
 * @property {string} [reason]
 */

/**
 * Split a bash command string into sub-command segments.
 * Splits on ;, &&, ||, bash keywords (do, then, else), subshell parens, and $(.
 * Does NOT split on | (pipe) — this is intentional. The no-curl-pipe-bash rule
 * matches "curl ... | bash" across a pipe. Splitting on | would break it.
 * Note: has no quote awareness, so "echo 'hello; world'" will split on the ;.
 * This is acceptable — false positives (too strict) are safer than false negatives.
 * @param {string} command
 * @returns {string[]}
 */
export function splitSubCommands(command) {
  try {
    const segments = command.split(/;|&&|\|\||(?:\$\()|[()]/);
    return segments.map(s => s.replace(/\b(do|then|else)\b/g, ";").split(";"))
      .flat()
      .map(s => s.trim())
      .filter(Boolean);
  } catch {
    return [command];
  }
}

/**
 * Test a single value against a pattern using the specified parser.
 * For glob patterns on non-path fields (e.g. command), post-processes the
 * generated regex to replace [^/] with . so that * matches any character.
 * @param {string} value
 * @param {string} pattern
 * @param {"glob" | "regex"} parser
 * @param {string} [flags]
 * @param {string} field
 * @returns {boolean}
 */
function testPattern(value, pattern, parser, flags, field) {
  if (!pattern) return false;
  if (parser === "regex") {
    return new RegExp(pattern, flags).test(value);
  }
  // Glob mode
  if (field === "file_path") {
    return micromatch.isMatch(value, pattern, { dot: true });
  }
  // Non-path fields: relax glob's [^/] to . so * matches slashes
  const re = micromatch.makeRe(pattern, { dot: true });
  if (!re) return false;
  const relaxed = new RegExp(re.source.replace(/\[\^\/\]/g, "."), re.flags);
  return relaxed.test(value);
}

/**
 * Test whether a declarative match object matches the tool input.
 * Every field in the match object must match (AND logic).
 * For the "command" field, also tests each sub-command segment.
 * @param {Record<string, string | MatchPattern>} match
 * @param {Record<string, any>} toolInput
 * @returns {boolean}
 */
function matchesInput(match, toolInput) {
  for (const [field, patternDef] of Object.entries(match)) {
    const value = toolInput[field];
    if (typeof value !== "string") return false;

    const pattern = typeof patternDef === "string" ? patternDef : patternDef.pattern;
    const parser = (typeof patternDef === "object" ? patternDef.parser : undefined) ?? "glob";
    const flags = typeof patternDef === "object" ? patternDef.flags : undefined;

    // Test full string first
    if (testPattern(value, pattern, parser, flags, field)) continue;

    // For command fields, also test each sub-command segment
    if (field === "command") {
      const segments = splitSubCommands(value);
      if (segments.some(seg => testPattern(seg, pattern, parser, flags, field))) continue;
    }

    return false;
  }
  return true;
}

/**
 * Evaluate tool input against rules using first-match-wins strategy.
 * @param {string} toolName
 * @param {Record<string, any>} toolInput
 * @param {DeclarativeRule[]} rules
 * @returns {EvalResult}
 */
export function evaluate(toolName, toolInput, rules) {
  for (const rule of rules) {
    try {
      // Check tool filter
      if (rule.tool) {
        const toolPattern = rule.tool instanceof RegExp
          ? rule.tool
          : new RegExp(`^(${rule.tool})$`);
        if (!toolPattern.test(toolName)) continue;
      }

      // Check match — support both declarative objects and legacy functions
      const matched = typeof rule.match === "function"
        ? rule.match(toolInput)
        : matchesInput(rule.match, toolInput);

      if (matched) {
        return {
          decision: rule.action,
          rule: rule.name,
          reason: rule.reason,
        };
      }
    } catch {
      // If a rule throws, skip it (fail open)
      continue;
    }
  }

  return { decision: "allow" };
}
