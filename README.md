# Agent Shield Auditor (`agent-shield-auditor`)

A security and compliance auditing skill package with virtual shield generation for AI agents, MCP toolchains, and automated workflows. Built around the `SKILL.md` specification, it provides zero-dependency local scanning, actionable hardening patterns, and a ready-to-use audit report template.

---

## Key Features

1. **Four-Vector Attack Surface Review**
   * **Prompt & Indirect Injection**: Identifies untrusted external inputs (web pages, emails, spreadsheets, uploaded files) concatenated directly into instructions without boundary isolation.
   * **Over-Privileged Tool Execution**: Flags wildcard command execution (such as `Bash(*)`), unrestricted file writes, or outbound network calls lacking allowlists.
   * **Credential & Sensitive Data Exposure**: Checks configurations, prompts, and logs for exposed API keys, private keys, environment secrets, or sensitive customer data.
   * **Unverified Runtime Policy Changes**: Detects autonomous attempts to alter firewall, kernel/eBPF, or production rules without human approval or provenance checks.

2. **Zero-Dependency Local Scanner (`scripts/audit_scanner.py`)**
   * Written with Python 3.9+ standard library only; no third-party packages required.
   * Scans a single file or an entire directory (`.md`, `.json`, `.yaml`, `.yml`, `.py`, `.sh`, `.txt`, `.env`).
   * Includes rules `SHIELD-001` through `SHIELD-005`, outputs structured JSON with severity counts (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), and exits with status code `2` when `CRITICAL` issues are found for easy automation integration.

3. **Virtual Shield & Hardening Patterns (`references/shield-patterns.md`)**
   * Ready-to-use **MCP / tool allowlist JSON policy** for least-privilege access.
   * **XML boundary wrapper** to isolate untrusted external payloads against indirect prompt injection.
   * **Three-step virtual shield rollout checklist** (provenance verification, benign-traffic dry run, and a 72-hour expiration TTL) to reduce false positives and prevent stale rules.

4. **Standardized Audit Report Template (`assets/audit-report-template.md`)**
   * Provides a clean report structure covering executive summary, vulnerability findings table, virtual shield configuration, and deployment sign-off checklist.

---

## Repository Structure

```text
agent-shield-auditor/
├── SKILL.md                          # Core skill instructions
├── README.md                         # English documentation
├── README.zh-CN.md                   # Chinese documentation
├── LICENSE                           # MIT License
├── scripts/
│   └── audit_scanner.py              # Zero-dependency Python security scanner
├── references/
│   └── shield-patterns.md            # Virtual shield and mitigation patterns
└── assets/
    ├── audit-report-template.md      # Markdown template for audit reports
    └── sample_vulnerable_agent.json  # Sample vulnerable agent config for testing
```

---

## How to Use

### Option 1: Run the Scanner Script Directly (30-Second Quickstart)

1. Extract the archive and enter the `agent-shield-auditor` directory:
   ```bash
   unzip agent-shield-auditor-v1.0.0.zip
   cd agent-shield-auditor
   ```
2. Run the scanner against the included sample file:
   ```bash
   python scripts/audit_scanner.py --target assets/sample_vulnerable_agent.json
   ```
3. Scan your own agent config, prompt, or project folder:
   ```bash
   python scripts/audit_scanner.py --target /path/to/your/agent-or-skill
   ```

### Option 2: Load as a Skill in Your Agent Environment

1. Copy the `agent-shield-auditor` folder into your skill directory (such as `~/.claude/skills/`, a project `.skills/` folder, or a `SKILL.md`-compatible platform).
2. Invoke it naturally in your prompt, for example:
   > "Use `agent-shield-auditor` to audit my MCP configuration, highlight high-risk permissions, and provide a least-privilege allowlist and human-approval gates."

### Option 3: Generate a Deliverable Audit Report

1. Review scanner findings alongside `references/shield-patterns.md` to pick appropriate allowlists, XML wrappers, or temporary guard rules.
2. Fill out `assets/audit-report-template.md` with your findings and sign-off items before production rollout.

---

## Important Notes

* **Avoid overly broad blocks**: Pair deny rules with explicit allowlists so legitimate workflows are not disrupted.
* **Dry-run before enforcing**: Test temporary rules against normal traffic in an audit/non-blocking mode first, and set an expiration TTL so temporary rules do not linger indefinitely.
