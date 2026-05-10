# deploy-via-pr

A short skill that walks an LLM agent through the steps of opening a
pull request to deploy a config change against the SBproxy gateway.

## When to use this skill

Use this skill when the operator asks the agent to roll out a YAML
edit, a new origin, or a policy tweak. The skill prefers small,
reviewable PRs over force-pushed branch updates.

## Steps

1. Identify the YAML file the change applies to.
2. Apply the edit on a fresh branch (`feat/<short-slug>`).
3. Run `sbproxy validate -c sb.yml` locally.
4. Open a PR and request review from a code owner.
5. After CI is green, merge with the squash strategy.

## Out of scope

- Direct production hotfixes. Use the `runbook/incident-response`
  skill for those.
- Reverting a bad release. Use the `runbook/rollback` skill for those.
