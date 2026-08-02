# Upgrade SBproxy

*Last modified: 2026-07-28*

Use this procedure for the Rust v1 release line. Upgrade a test or canary instance before the rest of a fleet, and keep the previous binary or image available until the new process has served traffic.

If you are moving from the archived Go `v0.1.x` implementation, read [MIGRATION.md](../MIGRATION.md) before this page. The config schema is called `schema-v1`; it is separate from the Rust binary version. Release-specific changes are in [CHANGELOG.md](../CHANGELOG.md).

## Before replacing anything

Choose a target release from the [GitHub releases page](https://github.com/soapbucket/sbproxy/releases), read its changelog entry, and record the version now running:

```bash
sbproxy --version
sbproxy validate /etc/sbproxy/sb.yml
cp /etc/sbproxy/sb.yml /etc/sbproxy/sb.yml.before-upgrade
```

`validate` compiles the configuration without binding a listener. Resolve errors here, not during a rollout. Keep secrets out of shell history and copy any referenced secret material with the backup method your platform already uses.

For a configuration change that accompanies the binary upgrade, preview it first:

```bash
sbproxy plan -f proposed-sb.yml --against /etc/sbproxy/sb.yml
sbproxy validate proposed-sb.yml
```

`plan` exits 2 when it finds changes. That is an informational result. It exits 3 for semantic validation errors.

## Install the target release

For an installer-managed node, pin the target tag instead of taking whatever release is latest:

```bash
export TARGET_VERSION=v1.9.0
curl -fsSL https://download.sbproxy.dev | SBPROXY_VERSION="$TARGET_VERSION" sh
sbproxy --version
```

Replace `v1.9.0` with the release tag you approved. The installer verifies the published SHA-256 checksum and verifies the Sigstore bundle when `cosign` is installed. See [SUPPLY-CHAIN.md](../SUPPLY-CHAIN.md) for the verification model.

For Docker, pull the same release tag, update the pinned image reference in your deployment manifest, and keep the explicit configuration command:

```bash
docker pull soapbucket/sbproxy:1.9.0
docker run --rm -p 8080:8080 \
  -v "$PWD/sb.yml:/etc/sbproxy/sb.yml:ro" \
  soapbucket/sbproxy:1.9.0 serve -f /etc/sbproxy/sb.yml
```

The published image has no default configuration command. In Kubernetes, update the `SBProxy.spec.image` tag and use the rollout procedure in [kubernetes.md](kubernetes.md).

## Roll out and verify

Restart one supervised instance, wait for it to become healthy, then continue with the next instance. For a systemd-managed node, that normally looks like this:

```bash
sudo systemctl restart sbproxy
sudo systemctl status sbproxy --no-pager
```

Make a representative request through the data plane. The `Host` header selects the origin you are testing:

```bash
curl -i -H 'Host: api.example.com' http://127.0.0.1:8080/status
```

For a running proxy with the admin server enabled, check the authenticated
`GET /api/health` endpoint on its configured bind address and port. The
default admin address is `127.0.0.1:9090`; see [admin.md](admin.md) for
authentication and reload checks. Watch access logs, error rate, latency,
provider failures, and budget behavior through the normal observation
window before expanding the rollout.

## Roll back

If the new binary fails validation, startup, or the canary traffic check, restore the prior binary or image and restart that instance. Restore the saved configuration only when the configuration changed as part of the rollout. Do not mix binary rollback with an unrelated configuration edit; validate the restored file before restarting.

For Kubernetes, restore the previous approved image tag and wait for the Deployment or StatefulSet rollout to complete. For Helm-managed operator changes, use `helm history` followed by `helm rollback`. The [operator quickstart](quickstart-operator.md) has the small-cluster commands.

After the fleet is stable on the intended version, remove the temporary `sb.yml.before-upgrade` copy according to your secret-retention policy.
