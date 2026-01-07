# Intermediate Representation (IR)

OccamO builds a language-agnostic IR so rules and call-graph logic can operate
consistently across languages.

## IRModule

- `file`: source file path (repo-relative)
- `language`: language ID (python, javascript, typescript, java, kotlin, go)
- `functions`: list of `IRFunction`
- `metadata`: optional metadata for plugins

## IRFunction

- `function_id`: stable ID derived from path + qualname + body hash
- `file`: file path
- `qualname`: qualified name (Class.method, function)
- `lineno`, `end_lineno`: function location
- `language`: language ID
- `calls`: list of `IRCall`
- `metadata`: optional metadata for plugins

## IRCall

- `name`: call name (function or method)
- `qualname`: resolved qualified name when available
- `lineno`: call line number
- `in_loop_depth`: loop nesting depth at call site
- `object_name`: receiver name (e.g., `User.objects`)
- `metadata`: optional metadata for plugins

## Stability and IDs

Function IDs are stable across refactors when the function body is unchanged.
This is the foundation for baseline comparisons and regression diffs.

The IR schema is stable across MINOR releases. Breaking changes are reserved
for MAJOR versions and will be documented.

## Plugins

Language plugins emit IR. Custom rules consume it (see `docs/RULE_SDK.md`).
