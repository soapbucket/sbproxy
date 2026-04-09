# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in sbproxy, please report it responsibly.

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please email: **security@soapbucket.com**

Include:

- A description of the vulnerability
- Steps to reproduce the issue
- The potential impact
- Any suggested fixes (optional)

## Response Timeline

- **Acknowledgment:** Within 2 business days
- **Initial assessment:** Within 5 business days
- **Fix and disclosure:** Coordinated with the reporter, typically within 30 days

## Scope

This policy applies to the latest released version of sbproxy. We do not provide security patches for older versions.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |
| < Latest | No      |

## Disclosure Policy

We follow coordinated disclosure. After a fix is released, we will publish a security advisory on GitHub with credit to the reporter (unless anonymity is requested).

## Security Best Practices

When deploying sbproxy in production:

- Run behind a firewall or load balancer that terminates TLS
- Use environment variables for secrets (API keys, credentials) - never hardcode them in config files
- Enable authentication on all public-facing origins
- Keep sbproxy updated to the latest version
- Review the [configuration examples](examples/) for secure defaults
