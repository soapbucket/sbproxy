# Certificate Pin Tool

A command-line utility to compute certificate pins for HTTPS hosts. This tool connects to a server, retrieves its TLS certificate chain, and computes SHA-256 pins for each certificate.

## Usage

```bash
go run main.go -host example.com [-port 443]
```

## Options

- `-host` (required): Hostname to connect to
- `-port` (optional): Port to connect on (default: 443)

## Example

```bash
$ go run main.go -host api.github.com
Computing certificate pins for api.github.com:443...

Found 2 certificate(s) in the chain:

Certificate 0 pin: 7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=
Certificate 1 pin: RRM1dGqnDFsCJXBTHky16vi1obOlCgFFn/yOhI/y+ho=

Configuration example:

"config": {
  "url": "https://api.github.com",
  "certificate_pinning": {
    "enabled": true,
    "pin_sha256": "7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=",
    "backup_pins": ["RRM1dGqnDFsCJXBTHky16vi1obOlCgFFn/yOhI/y+ho="]
  }
}
```

## What is Certificate Pinning?

Certificate pinning is a security technique that allows you to associate a host with its expected public key. When enabled, the proxy will reject connections if the server's certificate doesn't match the pinned value, protecting against:

- Compromised Certificate Authorities
- Man-in-the-middle attacks
- Rogue certificates

## Pin Format

Pins are base64-encoded SHA-256 hashes of the certificate's Subject Public Key Info (SPKI).

## Best Practices

1. **Pin Multiple Certificates**: Include backup pins for certificate rotation
2. **Monitor Expiry**: Set a `pin_expiry` date and monitor warnings
3. **Test Before Deployment**: Verify pins in development before production
4. **Rotation Plan**: Have a plan for rotating pins when certificates expire

## Integration

The computed pins can be added directly to your origin configuration:

```json
{
  "hostname": "api.example.com",
  "type": "proxy",
  "config": {
    "url": "https://api.example.com",
    "certificate_pinning": {
      "enabled": true,
      "pin_sha256": "<primary-pin>",
      "backup_pins": ["<backup-pin-1>", "<backup-pin-2>"],
      "pin_expiry": "2026-01-01T00:00:00Z"
    }
  }
}
```

## Security Notes

- Always verify the authenticity of the connection before using the computed pins
- Consider using backup pins from both the current and future certificates
- Set reasonable expiry dates to force pin rotation
- Monitor logs for pin mismatch errors which may indicate attacks or misconfigurations



