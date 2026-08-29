# Rotating an upstream credential

*Last modified: 2026-08-28*

Replacing an upstream provider secret without a window where requests fail.

`POST /admin/credentials/{id}/rotate` installs new material and keeps the old
material usable as a fallback for a bounded overlap. The new material is what
every request uses; the previous one is reached only when the new one will not
resolve, and only while the window is open. A rotation that works never
presents the retired secret, and a rotation that has not taken effect at the
provider yet does not take the deployment down.

Pass `grace_secs: 0` when the secret being replaced is compromised: the old
material is retired at once and there is no window.

`sb.yml` carries the runnable config and the curl walkthrough. See
`docs/key-management.md` for the rotation-cadence table and what the overlap
does and does not mean.
