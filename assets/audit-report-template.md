# AI Agent Static Security Review Report

- **Target System / Skill**: `{{target_name}}`
- **Audit Date**: `{{audit_date}}`
- **Overall Risk Rating**: `{{risk_rating}}`

## 1. Executive Summary
Summarize the review scope, suspicious patterns, and recommended next steps. State that this is a heuristic static review and does not prove exploitability or provide runtime protection.

## 2. Vulnerability & Risk Findings

| Rule ID | Severity | Location | Issue Description | Suggested Mitigation |
| :--- | :--- | :--- | :--- | :--- |
| SHIELD-001 | CRITICAL | Line X | Example finding | Restrict tool allowlist |

## 3. Suggested Mitigation Configuration
```json
{
  "example_only": true,
  "requires_human_review": true,
  "mitigations_to_validate": []
}
```

## 4. Sign-Off & Deployment Gate
- [ ] Secrets rotated and removed from prompt/config
- [ ] Representative benign cases reviewed for false positives
- [ ] Human approval is required for high-impact actions where appropriate
