---
name: agent-shield-auditor
description: Help review AI agent prompts, MCP tool schemas, and Skill/configuration files for selected suspicious patterns, then suggest hardening measures for human review. The bundled scanner is heuristic static analysis only; it does not prove exploitability or implement runtime protection. Use when the user asks for a preliminary review of agent configuration or permissions.
license: MIT
compatibility: Requires Python 3.9+ for running local rule scanner scripts.
metadata:
  author: rsplife
  version: "1.1.1"
---

# Agent Shield Auditor

Perform a preliminary, heuristic review of AI agent configurations and tool definitions. Report suspicious patterns and suggest possible mitigations; findings must be reviewed in context. This skill does not implement or enforce runtime shields.

## When to Use

* The user asks to audit an AI agent, `SKILL.md`, or MCP server tool permissions for security risks.
* The user wants to prevent prompt injection, unauthorized command execution, or API key / financial data leakage.
* The user wants suggestions for hardening an agent workflow, with human review before implementation.

## Steps

### 1. Inventory Agent Attack Surface
Inspect the provided agent prompt, tool schema, or logs across four risk vectors:
* **Prompt & Indirect Injection**: Untrusted external inputs (web pages, emails, CSV cells, user uploads) concatenated directly into system instructions without delimiter isolation.
* **Over-Privileged Tool Execution**: Wildcard shell access (`Bash(*)`), unrestricted file writes, or outbound HTTP requests without allowlists.
* **Data Exfiltration & Credential Exposure**: Potential leakage of `.env` secrets, API keys, wallet private keys, or customer PII in logs or outbound tool parameters.
* **Unverified Runtime Policy Changes**: Allowing an autonomous agent to modify firewall, kernel/eBPF, or production database rules without cryptographic verification or human approval.

### 2. Run Static & Payload Scan
Execute `scripts/audit_scanner.py` against a target file or directory to flag selected suspicious patterns and output structured JSON triage results:

```bash
python scripts/audit_scanner.py --target <path_to_file_or_dir>
# Or generate a Markdown report directly:
python scripts/audit_scanner.py --target <path_to_file_or_dir> --format md --output audit-report.md
```

### 3. Suggest Hardening Measures
Based on findings and `references/shield-patterns.md`, suggest options for a qualified human to review:
* **Severity Summary**: Critical / High / Medium / Low breakdown with exact line or field references.
* **Possible mitigation**: A least-privilege allowlist, an untrusted-input boundary, or a human-approval checkpoint. Do not claim the suggestion blocks an exploit unless it is implemented and tested in the target environment.
* **Human-in-the-Loop (HITL) Gate**: Explicit confirmation checkpoints for irreversible actions (payments, deletions, external network calls).

### 4. Output Using Standard Report Template
Format a preliminary review report using `assets/audit-report-template.md`. Clearly label unverified findings and the scope/limitations of the review.

## Gotchas

* **Do not over-block legitimate traffic**: A virtual shield that blocks valid business operations causes denial-of-service. Always pair deny rules with narrow allowlist parameters.
* **Signatures are not logic verification**: Cryptographic signing proves rule provenance, not rule safety. Always dry-run generated shields against benign test cases first.
