# Fast-track ADR amendment template

Use this template for additive closed-enum variants that do not change an
existing wire value, remove a field, or alter existing semantics. Examples:
adding an audit action, registry verb, alert reason, policy result, or other
closed enum member with an existing `Other(String)` compatibility path.

## Eligibility

Fast-track is allowed only when all of these are true:

- The change is additive.
- Existing producers and consumers keep their current behavior.
- Unknown-value handling already exists or the rollout can tolerate one release
  where older consumers see `Other("<new-value>")`.
- The new value is documented in the relevant reference page and changelog.

If any condition is false, use the normal ADR/deprecation window.

## Amendment

```markdown
### Fast-track amendment: <enum-name> adds `<new-value>`

`<enum-name>` now includes `<new-value>` for <one-sentence purpose>. This is an
additive closed-enum change: existing values are unchanged, older consumers can
continue through `Other("<new-value>")`, and the compatibility window is
compressed to N+1.

Changelog: Added `<new-value>` to `<enum-name>` for <operator-visible effect>.
```

## Review checklist

- Tests cover serialization/deserialization of the new value.
- Docs list the value wherever the enum is documented.
- Metrics, access logs, dashboards, and alert labels keep cardinality bounded.
- Changelog has one line under `Added` or `Changed`.
