#!/usr/bin/env python3
"""
chaos-detector.py — Scans existing rules for known attack patterns
grammar-curator-1 | CCC's third bred persistent agent

Scans the Grammar Engine's rules.jsonl and evolution.jsonl for
known attack vectors: XSS, SQLi, path traversal, code execution.
Can be run ad-hoc or scheduled as a cron job.
"""

import json
import re
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# ── Patterns (shared with rule-sanitizer, kept inline for standalone use) ──

XSS_PATTERN = re.compile(
    r"<script|javascript:|on\w+\s*=|<iframe|<object|<embed|eval\(|expression\(",
    re.IGNORECASE,
)

SQLI_PATTERN = re.compile(
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION)\b)|(--|#|;/\*|/\*!\d+\b)",
    re.IGNORECASE,
)

CODE_EXEC_PATTERN = re.compile(
    r"(__import__|import\s+os|import\s+subprocess|os\.system|os\.popen|subprocess\.call|"
    r"subprocess\.run|eval\(|exec\(|compile\(|input\(|open\(|\.spawn\(|\.popen\(|"
    r"rm\s+-rf\s+/|shutil\.rmtree|pathlib\.Path\(['\"]\s*/)",
    re.IGNORECASE,
)

PATH_TRAVERSAL_PATTERN = re.compile(r"\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f")

# ── Severity Mapping ─────────────────────────────────────────

SEVERITY = {
    "xss": "HIGH",
    "sqli": "CRITICAL",
    "code_exec": "CRITICAL",
    "path_traversal": "HIGH",
}

# ── Scanner ──────────────────────────────────────────────────

class ChaosDetector:
    def __init__(self, rules_file: Path, evolution_file: Path = None):
        self.rules_file = rules_file
        self.evolution_file = evolution_file
        self.findings = []

    def _scan_string(self, s: str, context: str, rule_id: str) -> list:
        hits = []
        if XSS_PATTERN.search(s):
            hits.append({"vector": "xss", "severity": SEVERITY["xss"], "context": context, "snippet": s[:200]})
        if SQLI_PATTERN.search(s):
            hits.append({"vector": "sqli", "severity": SEVERITY["sqli"], "context": context, "snippet": s[:200]})
        if CODE_EXEC_PATTERN.search(s):
            hits.append({"vector": "code_exec", "severity": SEVERITY["code_exec"], "context": context, "snippet": s[:200]})
        if PATH_TRAVERSAL_PATTERN.search(s):
            hits.append({"vector": "path_traversal", "severity": SEVERITY["path_traversal"], "context": context, "snippet": s[:200]})
        for hit in hits:
            hit["rule_id"] = rule_id
        return hits

    def scan_rules(self):
        if not self.rules_file.exists():
            return
        with open(self.rules_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rule = json.loads(line)
                except json.JSONDecodeError:
                    continue
                rid = rule.get("id", "unknown")

                # Scan name
                self.findings.extend(self._scan_string(rule.get("name", ""), "rule.name", rid))

                # Scan type (unlikely but possible)
                self.findings.extend(self._scan_string(rule.get("type", ""), "rule.type", rid))

                # Scan production recursively
                prod = rule.get("production", {})
                self._scan_dict(prod, "rule.production", rid)

    def _scan_dict(self, d: dict, prefix: str, rid: str):
        for k, v in d.items():
            self.findings.extend(self._scan_string(str(k), f"{prefix}[key]", rid))
            if isinstance(v, str):
                self.findings.extend(self._scan_string(v, f"{prefix}.{k}", rid))
            elif isinstance(v, dict):
                self._scan_dict(v, f"{prefix}.{k}", rid)
            elif isinstance(v, list):
                for i, item in enumerate(v):
                    if isinstance(item, str):
                        self.findings.extend(self._scan_string(item, f"{prefix}.{k}[{i}]", rid))
                    elif isinstance(item, dict):
                        self._scan_dict(item, f"{prefix}.{k}[{i}]", rid)

    def scan_evolution(self):
        if not self.evolution_file or not self.evolution_file.exists():
            return
        with open(self.evolution_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                rid = entry.get("rule", {}).get("id", "evolution_entry") if entry.get("rule") else "evolution_entry"
                # Scan the raw entry as a quick heuristic
                raw = json.dumps(entry)
                self.findings.extend(self._scan_string(raw, "evolution_log.entry", rid))

    def report(self) -> dict:
        by_vector = defaultdict(list)
        for f in self.findings:
            by_vector[f["vector"]].append(f)

        return {
            "scan_time": datetime.utcnow().isoformat() + "Z",
            "rules_file": str(self.rules_file),
            "evolution_file": str(self.evolution_file) if self.evolution_file else None,
            "total_findings": len(self.findings),
            "summary": {vec: len(items) for vec, items in by_vector.items()},
            "findings": self.findings,
            "recommendation": "Review CRITICAL findings immediately. Deactivate offending rules." if any(f["severity"] == "CRITICAL" for f in self.findings) else "No critical findings. Continue monitoring.",
        }


# ── CLI ────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Grammar Engine Chaos Detector")
    parser.add_argument("--rules", default="/home/ubuntu/.openclaw/workspace/data/recursive-grammar/rules.jsonl", help="Path to rules.jsonl")
    parser.add_argument("--evolution", default="/home/ubuntu/.openclaw/workspace/data/recursive-grammar/evolution.jsonl", help="Path to evolution.jsonl")
    parser.add_argument("--output", default=None, help="Write JSON report to file")
    args = parser.parse_args()

    detector = ChaosDetector(Path(args.rules), Path(args.evolution) if args.evolution else None)
    detector.scan_rules()
    detector.scan_evolution()
    report = detector.report()

    out = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(out)
        print(f"Report written to {args.output}")
    else:
        print(out)

    sys.exit(1 if report["total_findings"] > 0 else 0)
