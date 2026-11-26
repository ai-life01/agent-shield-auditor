# AI Agent Security & Virtual Shield Audit Report

- **Target System / Skill**: `{{target_name}}`
- **Audit Date**: `{{audit_date}}`
- **Overall Risk Rating**: `{{risk_rating}}`

## 1. Executive Summary
Brief overview of the agent's attack surface, tool privileges, and immediate virtual mitigation actions.

## 2. Vulnerability & Risk Findings

| Rule ID | Severity | Location | Issue Description | Recommended Virtual Shield |
| :--- | :--- | :--- | :--- | :--- |
| SHIELD-001 | CRITICAL | Line X | Example finding | Restrict tool allowlist |

## 3. Recommended Virtual Shield Configuration
```json
{
  "shield_id": "vs-temp-001",
  "ttl_hours": 72,
  "mode": "enforce_with_hitl",
  "blocked_vectors": []
}
```

## 4. Sign-Off & Deployment Gate
- [ ] Secrets rotated and removed from prompt/config
- [ ] Benign traffic dry-run passed (0% false positives)
- [ ] Human-in-the-loop gate enabled for high-risk actions
