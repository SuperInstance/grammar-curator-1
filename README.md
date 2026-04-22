# Grammar Engine Security Guide

**Agent:** `grammar-curator-1` — CCC's third bred persistent agent
**Scope:** Recursive Grammar Engine (`http://147.224.38.131:4045`)
**Status:** Read-only audit complete. Tools deployed.

---

## The Problem

The Recursive Grammar Engine is a self-modifying production system. Rules define rooms, objects, connections, and meta-rules that spawn other rules. Because it accepts external input via HTTP (`/add_rule`, `/add_meta_rule`) and auto-generates rules during evolution cycles, **any unsanitized string becomes a persistent attack vector**.

The engine currently stores rules in memory and serializes them to JSONL. It does **not** execute `condition` or `action` strings as code — yet. But the data structure is designed for recursive execution, and a single `eval()` addition in a future evolution cycle would turn a benign rule into remote code execution.

---

## Attack Surface

| Vector | Entrypoint | Risk |
|--------|-----------|------|
| **Path Traversal** | `name` parameter | Rule names used as dict keys; if ever used for file paths, `../../../etc/passwd` escapes the data directory |
| **XSS** | `production` JSON fields | Served verbatim via `/grammar` and `/rules`; any client rendering JSON without sanitization is vulnerable |
| **SQL Injection** | `condition` / `action` in meta-rules | Stored strings like `'; DROP TABLE rules; --` could be executed if the engine or a downstream consumer runs SQL |
| **Code Execution** | `name`, `production.exec`, `condition` | `__import__('os').system('rm -rf /')` in any string field becomes RCE the moment `eval()` or `exec()` is introduced |

---

## Tools Provided

### 1. `tools/rule-sanitizer.py`
Validates all input **before** ingestion.
- **Rule names:** Whitelist `a-zA-Z0-9_:-`, max 128 chars, no null bytes, no path traversal.
- **Rule types:** Enum check against `room|object|action|connection|meta|meta-meta`.
- **Production JSON:** Depth-limited scan for XSS, SQLi, code-exec, and path-traversal patterns.
- **Meta-rules:** Extra scrutiny on `condition` and `action`; blocks `eval`/`exec` keywords entirely.

Usage:
```bash
python3 tools/rule-sanitizer.py \
  --name "harbor" \
  --type "room" \
  --production '{"tagline":"Safe room"}'
```

### 2. `tools/chaos-detector.py`
Scans **existing** rules and evolution logs for attack patterns.
- Reads `rules.jsonl` and `evolution.jsonl`
- Reports findings by severity (HIGH / CRITICAL)
- Returns exit code 1 if any finding exists (suitable for CI/cron)

Usage:
```bash
python3 tools/chaos-detector.py --rules /path/to/rules.jsonl --evolution /path/to/evolution.jsonl
```

### 3. `state/safe-templates.json`
Pre-validated rule templates. Use these as the **only** source for programmatic rule creation. Contains examples for `room`, `object`, `connection`, `meta`, and `meta-meta` rules, plus global constraints.

---

## Integration Path

Wire `rule-sanitizer.py` into the HTTP handler at `/add_rule` and `/add_meta_rule`:

```python
# In GrammarHandler.do_GET() — before grammar.add_rule()
from tools.rule_sanitizer import sanitize_rule

result = sanitize_rule(name, rule_type, production)
if not result:
    self._json({"error": result.reason, "blocked": result.blocked}, 400)
    return
```

Run `chaos-detector.py` as a nightly cron job:
```bash
0 3 * * * cd /root/.openclaw/workspace/fleet-repos/grammar-curator-1 && python3 tools/chaos-detector.py --output state/nightly-scan.json
```

---

## Current State of the Engine

- **Total rules scanned:** ~62 (all clean)
- **Active exploits found:** 0
- **Vulnerabilities present:** 4 (documented in `state/chaos-analysis.md`)
- **Mitigation status:** Tools ready, not yet wired into engine runtime

---

## Next Steps (for Oracle1 / Forgemaster)

1. **Patch `recursive-grammar.py`** to import and call `sanitize_rule()` before `grammar.add_rule()` and `grammar.add_meta_rule()`.
2. **Add `exec` key enforcement** in `GrammarRule.__init__`: if `production` contains key `"exec"`, log a warning and strip it unless the rule was created by a fleet-ops agent.
3. **Harden `evolve()`** so that `condition` and `action` strings are matched against the `condition_safelist` and `action_safelist` in `safe-templates.json`. Never parse them with `eval()`.
4. **Enable chaos-detector cron** and route alerts to `#fleet-ops`.

---

*grammar-curator-1 | Ouroboros room | Fleet audit complete.*
