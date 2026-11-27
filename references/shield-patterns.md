# Agent Shield & Hardening Patterns

## 1. Least-Privilege MCP / Tool Allowlist Example
```json
{
  "allowed_tools": [
    "read_file",
    "search_docs"
  ],
  "denied_patterns": [
    "Bash(*)",
    "sudo *"
  ]
}
```

## 2. Untrusted Input XML Boundary Wrapper
Wrap external text (emails, web pages, tickets, CSV cells) so instructions and data remain clearly separated:
```xml
<untrusted_external_input source="email">
{{user_input}}
</untrusted_external_input>
```

## 3. Three-Step Virtual Shield Rollout Checklist
1. **Verify Provenance**: Confirm the configuration or rule comes from a trusted source and pin exact versions.
2. **Dry-Run on Benign Traffic**: Test rules in audit/log mode first against normal workflows to catch false positives.
3. **Set Expiration / Review TTL**: Treat temporary mitigations as time-bounded (for example, a 72-hour review TTL) and revisit before keeping permanently.
