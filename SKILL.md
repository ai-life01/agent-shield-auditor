---
name: agent-shield-auditor
description: Audit AI agent prompts, MCP tool schemas, and runtime logs for prompt injection, privilege escalation, and sensitive data leaks, and generate virtual runtime shields (allowlists, delimiter wrappers, and human-in-the-loop gates). Use when the user asks to audit an agent workflow, check MCP permissions, generate a virtual security patch, or secure an AI agent before deployment.
license: MIT
compatibility: Requires Python 3.9+ for running local rule scanner scripts.
metadata:
  author: rsplife
  version: "1.0.0"
---

# Agent Shield Auditor

Audit AI agent configurations, tool definitions, and runtime payloads to detect security vulnerabilities and generate lightweight virtual shields (policy rules, input sanitizers, and human-in-the-loop gates) before official upstream patches arrive.

## When to Use

* The user asks to audit an AI agent, `SKILL.md`, or MCP server tool permissions for security risks.
* The user wants to prevent prompt injection, unauthorized command execution, or API key / financial data leakage.
* The user needs a temporary "virtual shield" to block exploit payloads while keeping legitimate agent traffic flowing.

## Steps

### 1. Inventory Agent Attack Surface
Inspect the provided agent prompt, tool schema, or logs across four risk vectors:
* **Prompt & Indirect Injection**: Untrusted external inputs (web pages, emails, CSV cells, user uploads) concatenated directly into system instructions without delimiter isolation.
* **Over-Privileged Tool Execution**: Wildcard shell access (`Bash(*)`), unrestricted file writes, or outbound HTTP requests without allowlists.
* **Data Exfiltration & Credential Exposure**: Potential leakage of `.env` secrets, API keys, wallet private keys, or customer PII in logs or outbound tool parameters.
* **Unverified Runtime Policy Changes**: Allowing an autonomous agent to modify firewall, kernel/eBPF, or production database rules without cryptographic verification or human approval.

### 2. Run Static & Payload Scan
Execute `scripts/audit_scanner.py` against the target file or payload string to detect high-risk patterns and output a structured JSON severity score:

```bash
python scripts/audit_scanner.py --target <path_to_file_or_dir>
```

### 3. Generate Virtual Shield & Hardening Rules
Based on the findings and `references/shield-patterns.md`, output:
* **Severity Summary**: Critical / High / Medium / Low breakdown with exact line or field references.
* **Virtual Shield Rule**: A concrete, copy-pasteable blocking rule (JSON tool-policy allowlist, XML input wrapper, or runtime guard signature) that blocks the exploit vector without breaking normal requests.
* **Human-in-the-Loop (HITL) Gate**: Explicit confirmation checkpoints for irreversible actions (payments, deletions, external network calls).

### 4. Output Using Standard Report Template
Format the final audit report using `assets/audit-report-template.md` so it can be delivered directly to engineering teams or clients.

## Gotchas

* **Do not over-block legitimate traffic**: A virtual shield that blocks valid business operations causes denial-of-service. Always pair deny rules with narrow allowlist parameters.
* **Signatures are not logic verification**: Cryptographic signing proves rule provenance, not rule safety. Always dry-run generated shields against benign test cases first.
