#!/usr/bin/env python3
"""
rule-sanitizer.py — Grammar Engine Input Validation
grammar-curator-1 | CCC's third bred persistent agent

Validates rule names, types, and production JSON before ingestion
into the Recursive Grammar Engine. Standalone tool; can be wired
into /add_rule and /add_meta_rule handlers.
"""

import json
import re
import sys
from pathlib import Path

# ── Configuration ───────────────────────────────────────────

MAX_RULE_NAME_LEN = 128
MAX_PRODUCTION_DEPTH = 5
MAX_PRODUCTION_KEYS = 50
MAX_STRING_LEN = 4096
ALLOWED_RULE_TYPES = {"room", "object", "action", "connection", "meta", "meta-meta"}
ALLOWED_PRODUCTION_KEYS = {
    "tagline", "theme", "ml_concept", "parent_room", "from", "to", "condition",
    "action", "meta_type", "merged_from", "raw", "description", "icon", "color",
    "weight", "threshold", "quality", "exec",  # exec is allowed as a KEY but its VALUE is heavily restricted
}

# ── Regex Patterns ─────────────────────────────────────────

# Rejects path traversal, null bytes, control chars, and overly weird unicode
RULE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_\-:]+$")

# Detects HTML/JS injection payloads
XSS_PATTERN = re.compile(
    r"<script|javascript:|on\w+\s*=|<iframe|<object|<embed|eval\(|expression\(",
    re.IGNORECASE,
)

# Detects SQL injection fragments
SQLI_PATTERN = re.compile(
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION)\b)|(--|#|;/\*|/\*!\d+\b)",
    re.IGNORECASE,
)

# Detects Python code execution fragments
CODE_EXEC_PATTERN = re.compile(
    r"(__import__|import\s+os|import\s+subprocess|os\.system|os\.popen|subprocess\.call|"
    r"subprocess\.run|eval\(|exec\(|compile\(|input\(|open\(|\.spawn\(|\.popen\(|"
    r"rm\s+-rf\s+/|shutil\.rmtree|pathlib\.Path\(['\"]\s*/)",
    re.IGNORECASE,
)

# Detects path traversal
PATH_TRAVERSAL_PATTERN = re.compile(r"\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f")


# ── Validation Result ──────────────────────────────────────

class SanitizerResult:
    def __init__(self, valid: bool, reason: str = "", blocked: bool = False):
        self.valid = valid
        self.reason = reason
        self.blocked = blocked

    def to_dict(self):
        return {"valid": self.valid, "reason": self.reason, "blocked": self.blocked}

    def __bool__(self):
        return self.valid


# ── Core Validators ──────────────────────────────────────────

def validate_rule_name(name: str) -> SanitizerResult:
    if not name or not isinstance(name, str):
        return SanitizerResult(False, "Rule name must be a non-empty string")
    if len(name) > MAX_RULE_NAME_LEN:
        return SanitizerResult(False, f"Rule name exceeds {MAX_RULE_NAME_LEN} chars")
    if "\x00" in name or any(ord(c) < 32 for c in name):
        return SanitizerResult(False, "Rule name contains control characters")
    if not RULE_NAME_PATTERN.match(name):
        return SanitizerResult(False, "Rule name contains illegal characters (allowed: a-z, A-Z, 0-9, _, -, :)")
    if PATH_TRAVERSAL_PATTERN.search(name):
        return SanitizerResult(False, "Path traversal detected in rule name", blocked=True)
    if CODE_EXEC_PATTERN.search(name):
        return SanitizerResult(False, "Code execution pattern detected in rule name", blocked=True)
    return SanitizerResult(True)


def validate_rule_type(rule_type: str) -> SanitizerResult:
    if rule_type not in ALLOWED_RULE_TYPES:
        return SanitizerResult(False, f"Unknown rule type '{rule_type}'. Allowed: {ALLOWED_RULE_TYPES}")
    return SanitizerResult(True)


def _validate_production_value(key: str, value, depth: int = 0) -> SanitizerResult:
    if depth > MAX_PRODUCTION_DEPTH:
        return SanitizerResult(False, f"Production exceeds max nesting depth ({MAX_PRODUCTION_DEPTH})")

    if isinstance(value, str):
        if len(value) > MAX_STRING_LEN:
            return SanitizerResult(False, f"String value for '{key}' exceeds {MAX_STRING_LEN} chars")
        if XSS_PATTERN.search(value):
            return SanitizerResult(False, f"XSS payload detected in production['{key}']", blocked=True)
        if SQLI_PATTERN.search(value):
            return SanitizerResult(False, f"SQL injection payload detected in production['{key}']", blocked=True)
        if CODE_EXEC_PATTERN.search(value):
            return SanitizerResult(False, f"Code execution payload detected in production['{key}']", blocked=True)
        if PATH_TRAVERSAL_PATTERN.search(value):
            return SanitizerResult(False, f"Path traversal detected in production['{key}']", blocked=True)
        # Special handling for 'exec' key: if present, value must be a benign string or empty
        if key == "exec" and value.strip():
            return SanitizerResult(False, f"Production['exec'] is a restricted key. Non-empty values are blocked.", blocked=True)

    elif isinstance(value, dict):
        for k, v in value.items():
            res = _validate_production_value(k, v, depth + 1)
            if not res:
                return res

    elif isinstance(value, list):
        for idx, item in enumerate(value):
            res = _validate_production_value(f"{key}[{idx}]", item, depth + 1)
            if not res:
                return res

    elif isinstance(value, (int, float, bool)):
        pass  # primitives are safe

    elif value is None:
        pass

    else:
        return SanitizerResult(False, f"Disallowed type {type(value).__name__} in production['{key}']")

    return SanitizerResult(True)


def validate_production(production: dict) -> SanitizerResult:
    if not isinstance(production, dict):
        return SanitizerResult(False, "Production must be a JSON object (dict)")
    if len(production) > MAX_PRODUCTION_KEYS:
        return SanitizerResult(False, f"Production exceeds {MAX_PRODUCTION_KEYS} keys")

    for key in production.keys():
        if key not in ALLOWED_PRODUCTION_KEYS:
            return SanitizerResult(False, f"Unknown production key '{key}'. Allowed: {ALLOWED_PRODUCTION_KEYS}")

    return _validate_production_value("production", production)


def validate_meta_rule(condition: str, action: str) -> SanitizerResult:
    """Meta-rules store condition/action as strings. Extra scrutiny."""
    for field, label in [(condition, "condition"), (action, "action")]:
        if not isinstance(field, str):
            return SanitizerResult(False, f"Meta-rule {label} must be a string")
        if len(field) > MAX_STRING_LEN:
            return SanitizerResult(False, f"Meta-rule {label} exceeds {MAX_STRING_LEN} chars")
        # Block any attempt to smuggle Python code via condition/action
        if CODE_EXEC_PATTERN.search(field):
            return SanitizerResult(False, f"Code execution pattern in meta-rule {label}", blocked=True)
        if SQLI_PATTERN.search(field):
            return SanitizerResult(False, f"SQL injection pattern in meta-rule {label}", blocked=True)
        # Explicit eval/exec ban
        if re.search(r"\beval\b|\bexec\b", field, re.IGNORECASE):
            return SanitizerResult(False, f"Meta-rule {label} contains forbidden eval/exec keywords", blocked=True)
    return SanitizerResult(True)


# ── Main Entrypoint ────────────────────────────────────────

def sanitize_rule(name: str, rule_type: str, production: dict, meta_condition: str = None, meta_action: str = None) -> SanitizerResult:
    checks = [
        validate_rule_name(name),
        validate_rule_type(rule_type),
        validate_production(production),
    ]
    if meta_condition is not None or meta_action is not None:
        checks.append(validate_meta_rule(meta_condition or "", meta_action or ""))

    for check in checks:
        if not check:
            return check
    return SanitizerResult(True, "Rule passed all sanitization checks")


# ── CLI ────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Grammar Engine Rule Sanitizer")
    parser.add_argument("--name", required=True, help="Rule name")
    parser.add_argument("--type", required=True, help="Rule type")
    parser.add_argument("--production", required=True, help="Production JSON string")
    parser.add_argument("--condition", default=None, help="Meta-rule condition (optional)")
    parser.add_argument("--action", default=None, help="Meta-rule action (optional)")
    args = parser.parse_args()

    try:
        prod = json.loads(args.production)
    except json.JSONDecodeError as e:
        print(json.dumps(SanitizerResult(False, f"Invalid production JSON: {e}").to_dict()))
        sys.exit(1)

    result = sanitize_rule(args.name, args.type, prod, args.condition, args.action)
    print(json.dumps(result.to_dict(), indent=2))
    sys.exit(0 if result.valid else 1)
