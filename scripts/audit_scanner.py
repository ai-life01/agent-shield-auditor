#!/usr/bin/env python3
"""Agent Shield Auditor: heuristic static scanner for AI agent project files.

Python 3.9+ standard library only. This tool reports suspicious patterns; it is
not a substitute for contextual security review or runtime protection.
"""

import argparse
import fnmatch
import json
import re
import sys
from datetime import date
from pathlib import Path

SUPPORTED_SUFFIXES = {".md", ".json", ".yaml", ".yml", ".py", ".sh", ".txt", ".env", ".toml", ".ini"}
DEFAULT_EXCLUDED_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "env", "node_modules",
    "__pycache__", ".mypy_cache", ".pytest_cache", "dist", "build",
}
SECRET_PATTERN = re.compile(
    r"sk-[a-zA-Z0-9_-]{20,}|gh[pousr]_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|"
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    re.IGNORECASE,
)

RISK_RULES = [
    {
        "id": "SHIELD-001", "category": "Privilege Escalation", "severity": "CRITICAL",
        "pattern": r"(?:Bash\(\*\)|shell\s*:\s*true|subprocess\.Popen\([^\n]{0,240}shell\s*=\s*True|os\.system\s*\()",
        "description": "Potentially unrestricted shell or OS command execution detected.",
        "remediation": "Prefer explicit command allowlists, avoid shell=True, and require approval for destructive actions.",
    },
    {
        "id": "SHIELD-002", "category": "Credential & Secret Exposure", "severity": "CRITICAL",
        "pattern": r"(?:sk-[a-zA-Z0-9_-]{20,}|gh[pousr]_[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)",
        "description": "A string matching a common API key, access token, or private-key marker was detected.",
        "remediation": "Treat the value as potentially exposed: revoke/rotate real credentials, remove them from tracked files, and use a secret manager or scoped environment variables.",
    },
    {
        "id": "SHIELD-003", "category": "Prompt & Indirect Injection", "severity": "HIGH",
        "pattern": r"(?:ignore\s+(?:all\s+)?previous\s+instructions|disregard\s+(?:all\s+)?(?:prior|previous)\s+(?:rules|instructions)|\{\{\s*user_input\s*\}\})",
        "description": "A common instruction-override phrase or an unescaped user_input template marker was detected.",
        "remediation": "Treat external content as untrusted data, isolate it from system instructions, and review how interpolated input is handled. Text matching alone does not prove an exploitable injection.",
    },
    {
        "id": "SHIELD-004", "category": "Unbounded Network Egress", "severity": "HIGH",
        "pattern": r"(?:curl\s+[^\n]{0,160}\$\(|wget\s+https?://|requests\.(?:post|put)\([^\n]{0,200}verify\s*=\s*False|0\.0\.0\.0/0)",
        "description": "A potentially risky outbound network pattern or disabled TLS verification was detected.",
        "remediation": "Review the destination and data being sent, use domain allowlists where appropriate, and keep TLS certificate verification enabled.",
    },
    {
        "id": "SHIELD-005", "category": "Autonomous Runtime Modification", "severity": "MEDIUM",
        "pattern": r"(?:\bebpf\b|\biptables\b|\bufw\s+allow\b|\bchmod\s+777\b|\bsudo\s+)",
        "description": "A command or term associated with privileged OS/network policy changes was detected; context review is required.",
        "remediation": "Review whether the operation is necessary, minimize privileges, and require explicit human approval for production changes.",
    },
]


def _snippet(line: str) -> str:
    """Return a short evidence snippet without copying obvious secret-like strings."""
    clipped = line.strip()[:240]
    return SECRET_PATTERN.sub("[REDACTED_SECRET]", clipped)[:160]


def scan_text(content: str, filepath: str) -> list:
    findings = []
    for line_no, line in enumerate(content.splitlines(), start=1):
        for rule in RISK_RULES:
            if re.search(rule["pattern"], line, re.IGNORECASE):
                findings.append({
                    "rule_id": rule["id"], "severity": rule["severity"],
                    "category": rule["category"], "file": filepath, "line": line_no,
                    "snippet": _snippet(line), "description": rule["description"],
                    "remediation": rule["remediation"],
                })
    return findings


def _is_excluded(path: Path, root: Path, exclude_patterns: list) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        relative = path
    if any(part in DEFAULT_EXCLUDED_DIRS for part in relative.parts):
        return True
    relative_text = relative.as_posix()
    return any(fnmatch.fnmatch(relative_text, pattern) or fnmatch.fnmatch(path.name, pattern)
               for pattern in exclude_patterns)


def scan_path(target: Path, exclude_patterns=None, max_file_size=1_048_576) -> dict:
    exclude_patterns = exclude_patterns or []
    target = target.expanduser()
    if not target.exists():
        return {"error": f"Target not found: {target}", "files_scanned": 0, "files_skipped": 0,
                "total_findings": 0, "severity_summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}, "findings": []}

    if target.is_file():
        files = [target]
        root = target.parent
    elif target.is_dir():
        root = target
        files = []
        for candidate in target.rglob("*"):
            if candidate.is_symlink() or not candidate.is_file():
                continue
            if candidate.suffix.lower() not in SUPPORTED_SUFFIXES and candidate.name != ".env":
                continue
            if _is_excluded(candidate, root, exclude_patterns):
                continue
            files.append(candidate)
    else:
        return {"error": f"Target is not a regular file or directory: {target}", "files_scanned": 0, "files_skipped": 0,
                "total_findings": 0, "severity_summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}, "findings": []}

    all_findings = []
    files_scanned = 0
    files_skipped = 0
    for file_path in sorted(files):
        if file_path.is_symlink():
            files_skipped += 1
            continue
        try:
            if file_path.stat().st_size > max_file_size:
                files_skipped += 1
                continue
            content = file_path.read_text(encoding="utf-8", errors="replace")
            files_scanned += 1
            all_findings.extend(scan_text(content, str(file_path)))
        except OSError as exc:
            all_findings.append({
                "rule_id": "SCAN-ERR", "severity": "LOW", "category": "Read Error",
                "file": str(file_path), "line": 0, "snippet": "",
                "description": f"Unable to read file: {exc}",
                "remediation": "Check file permissions and encoding.",
            })

    summary = {severity: 0 for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    for finding in all_findings:
        summary[finding.get("severity", "LOW")] += 1

    return {"target": str(target), "files_scanned": files_scanned, "files_skipped": files_skipped,
            "total_findings": len(all_findings), "severity_summary": summary, "findings": all_findings}


def _md_escape(text: str) -> str:
    """Escape pipe characters and newlines so Markdown tables stay well-formed."""
    return str(text).replace("|", "\\|").replace("\r", " ").replace("\n", " ").strip()


def _overall_rating(summary: dict, has_error: bool) -> str:
    if has_error:
        return "ERROR (Scan Incomplete)"
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if summary.get(level, 0) > 0:
            return level
    return "CLEAN (No Heuristic Matches)"


def format_markdown_report(result: dict, audit_date: str = None) -> str:
    """Render a structured Markdown static security review report from scan results."""
    audit_date = audit_date or date.today().isoformat()
    target_name = result.get("target", "unknown")
    summary = result.get("severity_summary", {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0})
    findings = result.get("findings", [])
    has_error = bool(result.get("error")) or any(f.get("rule_id") == "SCAN-ERR" for f in findings)
    rating = _overall_rating(summary, has_error)

    lines = [
        "# AI Agent Static Security Review Report",
        "",
        f"- **Target System / Skill**: `{target_name}`",
        f"- **Audit Date**: `{audit_date}`",
        f"- **Overall Triage Rating**: `{rating}`",
        f"- **Files Scanned / Skipped**: `{result.get('files_scanned', 0)}` / `{result.get('files_skipped', 0)}`",
        f"- **Total Heuristic Findings**: `{result.get('total_findings', 0)}` "
        f"(CRITICAL: {summary.get('CRITICAL', 0)}, HIGH: {summary.get('HIGH', 0)}, "
        f"MEDIUM: {summary.get('MEDIUM', 0)}, LOW: {summary.get('LOW', 0)})",
        "",
        "## 1. Executive Summary",
    ]

    if result.get("error"):
        lines.append(f"- **Scan Error**: {_md_escape(result['error'])}")
    elif not findings:
        lines.append(
            "No heuristic risk patterns matched in the scanned files. Note that this is a preliminary "
            "static pattern check—it does not prove the absence of vulnerabilities or provide runtime protection."
        )
    else:
        lines.append(
            f"Scanned `{result.get('files_scanned', 0)}` file(s) under `{target_name}` and flagged "
            f"`{len(findings)}` heuristic pattern match(es) for human review. "
            "These findings are static triage indicators only; they do not prove exploitability or provide runtime protection."
        )

    lines.extend([
        "",
        "## 2. Vulnerability & Risk Findings",
        "",
    ])

    if not findings:
        lines.append("_No suspicious patterns detected._")
    else:
        lines.extend([
            "| Rule ID | Severity | Location | Snippet | Issue Description | Suggested Mitigation |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
        ])
        for item in findings:
            loc = f"`{_md_escape(item.get('file', ''))}:{item.get('line', 0)}`"
            snippet = f"`{_md_escape(item.get('snippet', ''))}`" if item.get("snippet") else "-"
            lines.append(
                f"| {_md_escape(item.get('rule_id', ''))} "
                f"| {_md_escape(item.get('severity', ''))} "
                f"| {loc} "
                f"| {snippet} "
                f"| {_md_escape(item.get('description', ''))} "
                f"| {_md_escape(item.get('remediation', ''))} |"
            )

    mitigations = sorted({item.get("rule_id") for item in findings if item.get("rule_id")})
    config_preview = json.dumps(
        {
            "example_only": True,
            "requires_human_review": True,
            "triggered_rules": mitigations,
            "recommended_controls": [
                "Restrict tool permissions to an explicit allowlist",
                "Isolate untrusted external input with XML delimiters",
                "Require human approval for privileged or irreversible actions",
            ],
        },
        indent=2,
    )

    lines.extend([
        "",
        "## 3. Suggested Mitigation Configuration",
        "```json",
        config_preview,
        "```",
        "",
        "## 4. Sign-Off & Deployment Gate",
        "- [ ] Secrets rotated and removed from prompt/config",
        "- [ ] Representative benign cases reviewed for false positives",
        "- [ ] Human approval is required for high-impact actions where appropriate",
        "",
        "> **Disclaimer**: Generated by `agent-shield-auditor` (heuristic static screening only). "
        "Review all findings in context before making deployment decisions.",
        "",
    ])

    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Heuristically scan AI agent configs and skill files for risky patterns.")
    parser.add_argument("--target", required=True, help="File or directory path to scan")
    parser.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                        help="Exclude relative-path or filename glob; may be repeated (example: '*.md')")
    parser.add_argument("--max-file-size", type=int, default=1_048_576,
                        help="Skip files larger than this many bytes (default: 1048576)")
    parser.add_argument("--format", choices=("json", "md"), default="json",
                        help="Output format: 'json' (default) or 'md' (Markdown security review report)")
    parser.add_argument("--output", metavar="FILE",
                        help="Write the scan report to FILE instead of only printing to stdout")
    args = parser.parse_args(argv)
    if args.max_file_size < 1:
        parser.error("--max-file-size must be at least 1 byte")

    result = scan_path(Path(args.target), args.exclude, args.max_file_size)
    if args.format == "md":
        rendered = format_markdown_report(result)
    else:
        rendered = json.dumps(result, indent=2, ensure_ascii=False)

    if args.output:
        out_path = Path(args.output).expanduser()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered + ("\n" if not rendered.endswith("\n") else ""), encoding="utf-8")
        print(f"Report written to {out_path} (findings: {result.get('total_findings', 0)})")
    else:
        print(rendered)

    if result.get("error"):
        return 1
    if any(item.get("rule_id") == "SCAN-ERR" for item in result.get("findings", [])):
        return 1
    if result.get("severity_summary", {}).get("CRITICAL", 0) > 0:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())