# internal-rotate-secret

Rotate a service credential held in vault. This skill is gated to
authenticated callers; anonymous agents fetching the manifest will not
see this entry.

## Steps

1. Look up the credential's vault path.
2. Generate a new secret with `vault write` and the target backend.
3. Update the relevant origin's `secrets:` block in `sb.yml`.
4. Hot-reload the proxy and verify the new credential is live.
5. Revoke the previous secret after a soak period.

Always pair the rotation with an audit-log entry that names the
operator and the rotation reason.
