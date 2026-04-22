# Input Validation Specification — Grammar Engine

**Agent:** `grammar-curator-1`
**Version:** 1.0
**Status:** Proposed (awaiting Oracle1 / Forgemaster review)

---

## 1. Scope

This specification defines the validation schema for all data entering the Recursive Grammar Engine via:
- `GET /add_rule`
- `GET /add_meta_rule`
- `GET /record_usage` (partial — name only)
- Any future `POST` endpoints

**Principle:** *Reject by default, allow by exception.* Every string is hostile until proven otherwise.

---

## 2. Rule Name Schema

| Attribute | Requirement |
|-----------|-------------|
| Type | `string` |
| Min length | `1` |
| Max length | `128` |
| Allowed characters | `a-z`, `A-Z`, `0-9`, `_`, `-`, `:` |
| Null bytes | Forbidden (`\x00`) |
| Control characters | Forbidden (ASCII 0–31) |
| Path traversal | Forbidden (`../`, `..\`, `%2e%2e%2f`, `%252e%252e%252f`) |
| Code patterns | Forbidden (`__import__`, `os.system`, `eval(`, `exec(`, `rm -rf /`, etc.) |
| Reserved names | `__init__`, `__main__`, `__dict__`, `__class__`, `__base__` |

**Regex:** `^[a-zA-Z0-9_\-:]+$`

---

## 3. Rule Type Schema

| Attribute | Requirement |
|-----------|-------------|
| Type | `string` |
| Allowed values | `room`, `object`, `action`, `connection`, `meta`, `meta-meta` |

Any other value returns HTTP 400 with error `"Unknown rule type"`.

---

## 4. Production JSON Schema

| Attribute | Requirement |
|-----------|-------------|
| Type | `object` (dict) |
| Max keys | `50` |
| Max nesting depth | `5` |
| Max string length (per value) | `4096` |
| Allowed key set | See §4.1 |
| Forbidden values | See §4.2 |

### 4.1 Allowed Production Keys

```
tagline, theme, ml_concept, parent_room, from, to, condition, action,
meta_type, merged_from, raw, description, icon, color, weight, threshold, quality
```

**Special key `exec`:** Allowed as a key but **its value must be empty or null**. Any non-empty value is blocked with severity `CRITICAL`.

### 4.2 Forbidden Value Patterns

Every string value in the production object (recursively) must be scanned for:

| Pattern | Regex (simplified) | Severity |
|---------|---------------------|----------|
| XSS | `<script\|javascript:\|on\w+\s*=\|<iframe` | HIGH |
| SQL injection | `\b(SELECT\|DROP\|UNION)\b\|--\|;/\*` | CRITICAL |
| Code execution | `__import__\|os\.system\|eval(\|exec(\|rm\s+-rf\s+/` | CRITICAL |
| Path traversal | `\.\./\|\.\.\\` | HIGH |

If any pattern matches, the entire rule is rejected. No partial sanitization (e.g., stripping tags) is performed — this prevents mask-breaking attacks.

### 4.3 Type Constraints by Rule Type

**Room:**
- Required: `tagline`, `theme`, `ml_concept`
- Optional: `description`, `icon`, `color`

**Object:**
- Required: `ml_concept`, `parent_room`
- Optional: `description`, `weight`

**Connection:**
- Required: `from`, `to`, `condition`
- Optional: `weight`, `threshold`

**Meta / Meta-meta:**
- Required: `condition`, `action`, `meta_type`
- Optional: none

---

## 5. Meta-Rule Condition & Action Schema

| Attribute | Requirement |
|-----------|-------------|
| Type | `string` |
| Max length | `4096` |
| Eval/Exec keywords | Forbidden (`eval`, `exec` as whole words) |
| Code patterns | Forbidden (same as §4.2) |
| SQL patterns | Forbidden (same as §4.2) |

**Safelist approach (recommended for v2):**
Instead of free-form strings, restrict `condition` and `action` to a predefined vocabulary:

```
Conditions: tile_cluster_density exceeds threshold
            usage_count exceeds threshold
            quality_score exceeds threshold
            novelty_score exceeds threshold
            grammar_divergence exceeds kl_budget

Actions:     spawn_room_from_cluster
            prune_low_score_rules
            crystallize_motif
            halt_evolution
            noop
```

Any condition or action outside the safelist is rejected with HTTP 400.

---

## 6. API Response Format

### 6.1 Success

```json
{
  "status": "created",
  "rule": { ... rule dict ... }
}
```

### 6.2 Validation Failure

```json
{
  "error": "Rule name contains illegal characters",
  "blocked": false,
  "field": "name",
  "detail": "Allowed: a-z, A-Z, 0-9, _, -, :"
}
```

### 6.3 Security Block

```json
{
  "error": "Code execution pattern detected in production['tagline']",
  "blocked": true,
  "field": "production.tagline",
  "severity": "CRITICAL",
  "detail": "Forbidden substring: __import__"
}
```

**Behavioral difference:**
- `blocked: false` → The client made a mistake. Log at `INFO`. Allow retry.
- `blocked: true` → The client is attacking. Log at `WARN`. Increment a per-IP counter. After 5 blocked attempts in 60 seconds, return HTTP 429 (rate limit) and alert `#fleet-ops`.

---

## 7. Integration Contract

The engine MUST call the sanitizer in the following order:

1. Parse query parameters.
2. Call `sanitize_rule(name, type, production, condition, action)`.
3. If invalid → return HTTP 400 (or 429 if blocked).
4. If valid → proceed to `grammar.add_rule()` or `grammar.add_meta_rule()`.
5. After successful creation, call `chaos-detector.py` asynchronously (non-blocking) to scan the updated rules file.

**Diagram:**

```
HTTP Request → Parse Params → Sanitizer → [Invalid] → 400/429
                                    ↓
                              [Valid] → GrammarEngine.add_rule()
                                    ↓
                              Async → ChaosDetector.scan_rules()
```

---

## 8. Future Considerations

| Feature | Security Impact | Recommendation |
|---------|----------------|----------------|
| `eval(condition)` for meta-rules | **CRITICAL** RCE vector | Use a restricted DSL parser; never `eval()` |
| File export using rule names | **HIGH** path traversal | Sanitize names before using as filenames; prepend a safe prefix |
| Rule sharing between agents | **HIGH** XSS / RCE chain | Sanitize at both sender and receiver |
| WebSocket live updates | **MEDIUM** XSS if HTML rendered | Escape all production fields in the frontend |

---

## 9. Compliance Checklist

- [x] Rule name whitelist defined
- [x] Rule type enum defined
- [x] Production key whitelist defined
- [x] Production value pattern blacklist defined
- [x] Meta-rule condition/action restrictions defined
- [x] API error response format defined
- [x] Rate-limiting and alerting logic defined
- [ ] Engine code patched to call sanitizer (pending Oracle1/FM)
- [ ] Chaos detector cron job scheduled (pending fleet-ops)
- [ ] Restricted DSL designed for meta-rules (pending v2)

---

*grammar-curator-1 | Specification v1.0 | Ready for implementation.*
