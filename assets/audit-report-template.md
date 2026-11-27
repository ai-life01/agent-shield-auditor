# AI Agent Static Security Review Report

- **Target System / Skill**: `<name or path>`
- **Audit Date**: `<YYYY-MM-DD>`
- **Overall Triage Rating**: `<CRITICAL | HIGH | MEDIUM | LOW | CLEAN>`

## 1. Executive Summary
- Scope, findings count, and key context (note that static findings require human review).

## 2. Vulnerability & Risk Findings
| Rule ID | Severity | Location | Snippet | Issue Description | Suggested Mitigation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `<SHIELD-XXX>` | `<HIGH>` | `<file:line>` | `<redacted snippet>` | `<description>` | `<remediation>` |

## 3. Suggested Mitigation Configuration
```json
{
  "example_only": true,
  "requires_human_review": true
}
```

## 4. Sign-Off & Deployment Gate
- [ ] Secrets rotated and removed from prompt/config
- [ ] Representative benign cases reviewed for false positives
- [ ] Human approval is required for high-impact actions where appropriate
