# Guardrails Allowlist Process

The `.guardrails-allow.json` file provides temporary exceptions when the scanner must ignore a specific environment variable name. Use this mechanism sparingly and document every entry.

## File Format
```json
{
  "env_names": [
    "EXAMPLE_TEMP_TOKEN__EXP_2025-12-31"
  ]
}
```

## Approval Steps
1. **Justification** – open a ticket describing why the variable cannot be renamed or removed immediately.
2. **Expiry tag** – append `__EXP_YYYY-MM-DD` to each allowlisted key so reviewers can confirm the sunset date. The scanner team prunes expired entries during triage.
3. **Reviewer sign-off** – obtain approval from the security reviewer listed in the ticket. Add a note to the PR summarising the risk, mitigation plan, and expiry.
4. **Follow-up task** – create a backlog item to remove the allowlist entry before the expiry date. CI will fail if the expiry date has passed.

## CI Expectations
- Pull Request CI posts a comment highlighting any allowlisted entries.
- Builds must include a plan to remediate the root cause before the expiry date; long-term exceptions should convert to design changes instead.
- The pipeline rejects commits where the allowlist is missing the required `__EXP_` suffix.

## Removal Checklist
- Update application code or infrastructure to eliminate the temporary secret or rename the variable.
- Delete the key from `.guardrails-allow.json`.
- Run `python -m scanner ...` locally to confirm the allowlist is no longer needed.
