# LDAP directory-bind authentication

*Last modified: 2026-08-19*

Authenticate requests against an LDAP or Active Directory server with a
directory bind. The client sends ordinary HTTP Basic credentials; the
proxy composes a bind DN from `uid_attribute` and `base_dn` and
attempts an LDAP simple bind with the supplied password. The bind
result is the only signal used: a successful bind authenticates the
request and attributes it to the username, anything else refuses it.
The password is never stored, never forwarded upstream, and never
logged.

Two failure modes stay separate on purpose. Wrong credentials get a
`401`. A directory the proxy cannot reach gets a `503`: the auth
boundary fails closed, so an LDAP outage refuses requests instead of
admitting them.

## You need a real directory

Unlike the other auth examples, this one cannot be exercised against
`test.sbproxy.dev`: the bind goes to the LDAP server named in `url`,
and the shipped config points at a placeholder
(`ldaps://directory.internal:636`). Without a reachable directory
every authenticated request answers `503`, which is the fail-closed
posture doing its job.

For a local fixture, an OpenLDAP container works:

```bash
docker run --rm -p 1389:1389 \
  -e LDAP_ROOT=dc=example,dc=org \
  -e LDAP_USERS=alice -e LDAP_PASSWORDS=s3cret \
  bitnami/openldap:latest
```

That directory listens on plaintext port 1389 and creates
`uid=alice,ou=users,dc=example,dc=org` with password `s3cret`. Point
the example at it by editing `sb.yml`:

```yaml
    authentication:
      type: ldap_auth
      url: ldap://127.0.0.1:1389
      base_dn: ou=users,dc=example,dc=org
      uid_attribute: uid
      allow_insecure: true   # local fixture only; see below
```

`allow_insecure: true` is required for a plaintext `ldap://` URL with
no StartTLS, because a simple bind sends the password in the clear.
The proxy refuses such a config at load time unless you opt in
explicitly. In production use `ldaps://` (as the shipped config does)
or `use_tls: true` to upgrade an `ldap://` connection with StartTLS;
both ride the proxy's rustls stack. With `tls_verify: true` (the
default) the `url` host must match the directory certificate's host.

## Run

```bash
make run CONFIG=examples/auth-ldap/sb.yml
```

## Try it

With the fixture directory running and `sb.yml` pointed at it:

```bash
# 200 - the directory accepts the bind for uid=alice
curl -i -u alice:s3cret -H 'Host: ldap.local' http://127.0.0.1:8080/get

# 401 - wrong password: the directory refuses the bind
curl -i -u alice:wrong -H 'Host: ldap.local' http://127.0.0.1:8080/get

# 401 - no credentials offered
curl -i -H 'Host: ldap.local' http://127.0.0.1:8080/get

# 503 - stop the directory container, then retry: the proxy refuses
curl -i -u alice:s3cret -H 'Host: ldap.local' http://127.0.0.1:8080/get
```

An empty password is refused by the proxy itself, without consulting
the directory: RFC 4513 defines a name-plus-empty-password bind as an
*unauthenticated* bind that many directories answer with success, and
treating that as proof of identity is the classic LDAP bypass.

## Fields

| Field | Default | Description |
|-------|---------|-------------|
| `url` | required | `ldap://host[:port]` or `ldaps://host[:port]` |
| `base_dn` | required | Base DN the user RDN is appended to |
| `uid_attribute` | `cn` | Attribute the username is bound under |
| `use_tls` | `false` | StartTLS upgrade for `ldap://` URLs |
| `tls_verify` | `true` | Verify the directory's TLS certificate |
| `allow_insecure` | `false` | Accept plaintext `ldap://` with no StartTLS |
| `timeout_secs` | `5` | Deadline for the connect + bind exchange |

Note the latency shape: this provider makes one directory round-trip
per request, like `forward_auth` and unlike every static-credential
provider. Budget `timeout_secs` accordingly; on timeout the request is
refused with a `503`.
