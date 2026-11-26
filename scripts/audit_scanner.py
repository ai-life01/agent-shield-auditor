#!/usr/bin/env python3
"""
Agent Shield Auditor - Static Security & Risk Scanner
Zero external dependencies (Python 3.9+ standard library only).
"""

import argparse
import json
import re
import sys
from pathlib import Path

RISK_RULES = [
    {
        "id": "SHIELD-001",
        "category": "Privilege Escalation",
        "severity": "CRITICAL",
        "pattern": r"(Bash\(\*\)|shell\s*:\s*true|subprocess\.Popen\(.*shell=True|os\.system\()",
        "description": "Unrestricted shell execution detected. Agent can execute arbitrary OS commands.",
        "remediation": "Restrict allowed commands to explicit allowlists (e.g., Bash(git:status)) and disable shell=True."
    },
    {
        "id": "SHIELD-002",
        "category": "Credential & Secret Exposure",
        "severity": "CRITICAL",
        "pattern": r"(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{30,}|AKIA[0-9A-Z]{16}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)",
        "description": "Hardcoded API key, access token, or private key detected in agent configuration or prompt.",
        "remediation": "Remove plaintext secrets immediately; inject via scoped environment variables or secret manager."
    },
    {
        "id": "SHIELD-003",
        "category": "Prompt & Indirect Injection",
        "severity": "HIGH",
        "pattern": r"(ignore (all )?previous instructions|system prompt|you are now|disregard prior rules|\{\{\s*user_input\s*\}\})",
        "description": "Potential prompt injection payload or unescaped user input interpolation detected.",
        "remediation": "Wrap untrusted external data in XML boundary tags (<untrusted_data>) and strip instruction overrides."
    },
    {
        "id": "SHIELD-004",
        "category": "Unbounded Network Egress",
        "severity": "HIGH",
        "pattern": r"(curl\s+.*\$\(|wget\s+http|requests\.(post|put)\(.*verify=False|0\.0\.0\.0/0)",
        "description": "Unrestricted outbound network call or disabled TLS verification detected.",
        "remediation": "Enforce strict domain allowlists and require TLS certificate verification."
    },
    {
        "id": "SHIELD-005",
        "category": "Autonomous Runtime Modification",
        "severity": "MEDIUM",
        "pattern": r"(ebpf|iptables|ufw\s+allow|chmod\s+777|sudo\s+)",
        "description": "Agent attempts or configures low-level OS/network policy modifications without human gate.",
        "remediation": "Require cryptographic signature verification and explicit human-in-the-loop approval before applying runtime shields."
    }
]


def scan_text(content: str, filepath: str) -> list:
    findings = []
    lines = content.splitlines()
    for line_no, line in enumerate(lines, start=1):
        for rule in RISK_RULES:
            if re.search(rule["pattern"], line, re.IGNORECASE):
                findings.append({
                    "rule_id": rule["id"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "file": filepath,
                    "line": line_no,
                    "snippet": line.strip()[:120],
                    "description": rule["description"],
                    "remediation": rule["remediation"]
                })
    return findings


def scan_path(target: Path) -> dict:
    all_findings = []
    files_scanned = 0

    if target.is_file():
        files = [target]
    elif target.is_dir():
        files = [p for p in target.rglob("*") if p.is_file() and p.suffix in {".md", ".json", ".yaml", ".yml", ".py", ".sh", ".txt", ".env"}]
    else:
        return {"error": f"Target not found: {target}"}

    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
            files_scanned += 1
            all_findings.extend(scan_text(text, str(f)))
        except Exception as exc:
            all_findings.append({
                "rule_id": "SCAN-ERR",
                "severity": "LOW",
                "category": "Read Error",
                "file": str(f),
                "line": 0,
                "snippet": "",
                "description": str(exc),
                "remediation": "Check file permissions and encoding."
            })

    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for item in all_findings:
        sev = item.get("severity", "LOW")
        if sev in summary:
            summary[sev] += 1

    return {
        "files_scanned": files_scanned,
        "total_findings": len(all_findings),
        "severity_summary": summary,
        "findings": all_findings
    }


def main():
    parser = argparse.ArgumentParser(description="Audit AI Agent configs and prompts for security risks.")
    parser.add_argument("--target", required=True, help="File or directory path to audit")
    args = parser.parse_args()

    result = scan_path(Path(args.target))
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if result.get("severity_summary", {}).get("CRITICAL", 0) > 0:
        sys.exit(2)


if __name__ == "__main__":
    main()
