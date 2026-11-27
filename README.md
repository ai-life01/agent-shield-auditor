# Agent Shield Auditor (`agent-shield-auditor`)

> A lightweight, zero-dependency heuristic static security scanner and hardening guide for AI agent, MCP, and Skill configurations.

**Language:** [🇺🇸 English](README.md) | [🇨🇳 简体中文](README.zh-CN.md)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-green.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/Version-1.1.0-orange.svg)](CHANGELOG.md)
[![YouTube Demo](https://img.shields.io/badge/Demo-YouTube-red.svg)](https://youtu.be/1bB5ixiZ0fA)

`agent-shield-auditor` runs locally with Python 3.9+ standard library only (no third-party dependencies). It flags selected suspicious patterns for human review—it does **not** prove exploitability or provide active runtime protection.

📺 **Video Walkthrough**: [Watch the step-by-step demo on YouTube](https://youtu.be/1bB5ixiZ0fA) | [View the X (Twitter) thread](https://x.com/lilisa2099/status/2126021966759153738)

---

## Key Features

1. **Four-Vector Attack Surface Review**
   * **Prompt & Indirect Injection (`SHIELD-003`)**: Flags common instruction-override phrases and unescaped user-input template markers (`{{user_input}}`) for review.
   * **Over-Privileged Tool Execution (`SHIELD-001`)**: Flags broad shell execution patterns (`Bash(*)`, `shell=True`, `os.system()`); coverage is intentionally focused on high-signal patterns.
   * **Credential & Sensitive Data Exposure (`SHIELD-002`)**: Checks for common API-token and private-key patterns. Matched secret-like strings are automatically redacted in evidence snippets.
   * **Unbounded Network & Runtime Policy Changes (`SHIELD-004`, `SHIELD-005`)**: Flags risky outbound network calls, disabled TLS verification, and privileged OS/firewall commands (`sudo`, `iptables`, `ufw`, `ebpf`, `chmod 777`).

2. **Zero-Dependency Local Scanner (`scripts/audit_scanner.py`)**
   * Written with Python 3.9+ standard library only; no `pip install` required.
   * Scans a single file or supported files in a directory (`.md`, `.json`, `.yaml`, `.yml`, `.py`, `.sh`, `.txt`, `.env`, `.toml`, `.ini`). Skips common generated/dependency directories, symlinks, and files larger than 1 MiB by default.
   * Supports both **JSON output (`--format json`)** for automation/CI and **one-click Markdown audit reports (`--format md --output report.md`)** for human review and handoff.
   * Standardized CLI exit codes:
     * `0`: Clean scan (no `CRITICAL` findings or read errors)
     * `1`: Missing target path or file read error
     * `2`: One or more `CRITICAL` heuristic patterns detected

3. **Virtual Shield & Hardening Patterns (`references/shield-patterns.md`)**
   * Ready-to-use **MCP / tool allowlist JSON policy** for least-privilege access.
   * **XML boundary wrapper** to isolate untrusted external payloads against indirect prompt injection.
   * **Three-step virtual shield rollout checklist** (provenance verification, benign-traffic dry run, and a 72-hour expiration TTL) to reduce false positives and prevent stale rules.

4. **Standardized Audit Report Template (`assets/audit-report-template.md`)**
   * Provides a clean report structure covering executive summary, findings table, mitigation configuration, and deployment sign-off checklist (also auto-populated when running `--format md`).

---

## Repository Structure

```text
agent-shield-auditor/
├── .github/
│   └── workflows/
│       └── test.yml                  # GitHub Actions CI for unit tests
├── SKILL.md                          # Core agent skill instructions
├── README.md                         # English documentation
├── README.zh-CN.md                   # Chinese documentation
├── CHANGELOG.md                      # Version history
├── LICENSE                           # MIT License
├── scripts/
│   └── audit_scanner.py              # Zero-dependency Python security scanner
├── references/
│   └── shield-patterns.md            # Virtual shield and mitigation patterns
├── assets/
│   ├── audit-report-template.md      # Markdown template for audit reports
│   └── sample_vulnerable_agent.json  # Sample vulnerable agent config for testing
└── tests/
    ├── __init__.py
    └── test_audit_scanner.py         # Standard library unittest suite
```

---

## How to Use

### Option 1: Run the Scanner Script Directly (30-Second Quickstart)

1. Clone the repository or extract the release archive and enter the directory:
   ```bash
   git clone https://github.com/ai-life01/agent-shield-auditor.git
   cd agent-shield-auditor
   ```
   *(Or if using the release zip: `unzip agent-shield-auditor-v1.1.0-v4.zip && cd agent-shield-auditor`)*
2. Run the scanner against the included sample file (JSON output):
   ```bash
   python scripts/audit_scanner.py --target assets/sample_vulnerable_agent.json
   ```
3. Generate a readable Markdown security review report directly (`--format md`):
   ```bash
   python scripts/audit_scanner.py --target assets/sample_vulnerable_agent.json --format md --output audit-report.md
   ```
4. Scan your own agent config, prompt, or project folder:
   ```bash
   python scripts/audit_scanner.py --target /path/to/your/agent-or-skill --format md --output my-audit-report.md
   ```

#### Example JSON Output

```json
{
  "target": "assets/sample_vulnerable_agent.json",
  "files_scanned": 1,
  "files_skipped": 0,
  "total_findings": 4,
  "severity_summary": {
    "CRITICAL": 2,
    "HIGH": 1,
    "MEDIUM": 1,
    "LOW": 0
  }
}
```

### Option 2: Load as a Skill in Your Agent Environment

1. Copy the `agent-shield-auditor` folder into your skill directory (such as `~/.claude/skills/`, a project `.skills/` folder, or a `SKILL.md`-compatible platform).
2. Invoke it naturally in your prompt, for example:
   > "Use `agent-shield-auditor` to audit my MCP configuration, highlight high-risk permissions, and provide a least-privilege allowlist and human-approval gates."

### Option 3: Review & Sign Off on the Generated Markdown Report

1. Open the generated `.md` report (or fill out `assets/audit-report-template.md`) alongside `references/shield-patterns.md` to pick appropriate allowlists, XML wrappers, or temporary guard rules.
2. Complete the sign-off checklist items before production rollout.

---

## Excluding Files & Running Tests

Use `--exclude` to skip documentation, fixtures, or other files that are not part of the target under review. You can pass it more than once:

```bash
python scripts/audit_scanner.py --target ./my-agent --exclude "README.md" --exclude "tests/*"
```

> **Tip:** If the target directory contains documentation or test fixtures, use `--exclude` to avoid treating examples as target findings. Do not scan this scanner repository itself as a representative agent project.

Run the included unit test suite with:

```bash
python -m unittest discover -v
```

---

## Important Notes & Limitations

* **Avoid overly broad blocks**: Pair deny rules with explicit allowlists so legitimate workflows are not disrupted.
* **This scanner does not enforce policies**: The reference shield patterns are guidance templates, not an active runtime shield. Validate all recommendations in context.
* **Review every finding**: Static pattern matches can produce false positives or miss real vulnerabilities. Do not treat a clean scan as proof of security.
* **Dry-run before enforcing**: Test any separately implemented temporary rules against normal traffic before enabling enforcement.

---

## Contact & Feedback

* **Bug Reports & Feature Requests**: [GitHub Issues](https://github.com/ai-life01/agent-shield-auditor/issues)
* **Video Walkthrough**: [Watch the Demo on YouTube](https://youtu.be/1bB5ixiZ0fA)
* **Updates & Quick Questions / Preliminary Review Assistance**: [X (@lilisa2099)](https://x.com/lilisa2099) · [Demo Post](https://x.com/lilisa2099/status/2126021966759153738)
* **Email**: `aikanhai677@gmail.com`
