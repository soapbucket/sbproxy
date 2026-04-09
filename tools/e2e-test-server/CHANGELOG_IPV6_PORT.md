# E2E Test Server - IPv6 Support and Port Change

**Date:** November 7, 2025

## Summary of Changes

This update addresses port conflicts with the main proxy server and adds IPv6 support for testing purposes.

## Changes Made

### 1. HTTPS Port Change

**Previous:** Port `8443` (conflicted with proxy default)  
**New:** Port `9443` (avoids conflict)

**Rationale:** The proxy server commonly uses port 8443 for HTTPS. Running both the proxy and e2e-test-server simultaneously on the same machine would cause port conflicts. Changing the default to 9443 allows both services to run side-by-side during testing.

### 2. IPv6 Support

Added a new `--bind` flag that supports:
- **IPv4 addresses** (e.g., `127.0.0.1`)
- **IPv6 addresses** (e.g., `::1`, `fe80::1`)
- **All interfaces** (default when flag is omitted)

The implementation properly handles IPv6 address formatting in URLs (wrapping in brackets `[::1]:9443`).

### 3. Updated Files

#### Code Changes
- `main.go`
  - Changed default `httpsPort` from `8443` to `9443`
  - Added `bindAddress` flag for IPv4/IPv6 binding
  - Updated all server start functions to use `getListenAddr()` helper
  - Added IPv6-aware display formatting in startup logs
  - Added `getListenAddr()` helper function to properly format listen addresses

#### Documentation Changes
- `README.md`
  - Updated default HTTPS port documentation
  - Added IPv6 support section with examples
  - Added bind address usage examples

- `MIGRATION_GUIDE.md`
  - Updated port mapping table to reflect new HTTPS port

- `CONSOLIDATION_SUMMARY.md`
  - Noted HTTPS port change and IPv6 support

#### Kubernetes Configuration
- `k8s/e2e-test-server.yaml`
  - Updated container port from `8443` to `9443`
  - Updated service targetPort mapping

## Usage Examples

### Default Usage (All Interfaces)
```bash
./e2e-test-server
# HTTP:  http://localhost:8090
# HTTPS: https://localhost:9443
# WS:    ws://localhost:8091
# GraphQL: http://localhost:8092/graphql
```

### IPv6 Loopback
```bash
./e2e-test-server -bind="::1"
# HTTP:  http://[::1]:8090
# HTTPS: https://[::1]:9443
# WS:    ws://[::1]:8091
# GraphQL: http://[::1]:8092/graphql
```

### IPv6 All Interfaces
```bash
./e2e-test-server -bind="::"
# Listens on all IPv6 interfaces
```

### IPv4 Specific Address
```bash
./e2e-test-server -bind="127.0.0.1"
# HTTP:  http://127.0.0.1:8090
# HTTPS: https://127.0.0.1:9443
# WS:    ws://127.0.0.1:8091
# GraphQL: http://127.0.0.1:8092/graphql
```

### Custom Ports with IPv6
```bash
./e2e-test-server -bind="::1" -https-port=10443
# HTTPS: https://[::1]:10443
```

## Testing IPv6 Support

### Test IPv6 HTTP Endpoint
```bash
# Start server on IPv6 loopback
./e2e-test-server -bind="::1"

# Test with curl
curl http://[::1]:8090/health
```

### Test IPv6 HTTPS Endpoint
```bash
# Test HTTPS (with self-signed cert)
curl -k https://[::1]:9443/health
```

### Test IPv6 WebSocket
```bash
# Using websocat
websocat ws://[::1]:8091/echo
```

## Breaking Changes

⚠️ **HTTPS Default Port Changed**

If you have scripts or configurations that reference the HTTPS endpoint at port `8443`, you will need to update them to use `9443`, or explicitly set the port:

```bash
# Option 1: Update your scripts to use 9443
curl https://localhost:9443/test/simple-200

# Option 2: Explicitly set the old port if needed
./e2e-test-server -https-port=8443
```

## Backward Compatibility

All previous functionality is preserved:
- Custom port flags still work (`-http-port`, `-https-port`, etc.)
- Configuration files remain unchanged
- All HTTP/HTTPS/WebSocket/GraphQL endpoints work identically
- Only the **default** HTTPS port has changed

## Migration Checklist

If you're updating from a previous version:

- [ ] Update any scripts referencing `https://localhost:8443` to use `https://localhost:9443`
- [ ] Update Kubernetes manifests if you're using hardcoded ports
- [ ] Update CI/CD pipelines that may reference the old port
- [ ] Test IPv6 support if needed for your use case
- [ ] Review and update any documentation or runbooks

## Implementation Details

### Address Formatting Logic

The `getListenAddr()` helper function properly formats addresses based on IP type:

```go
func getListenAddr(bindAddr string, port int) string {
    if bindAddr == "" {
        // Listen on all interfaces (both IPv4 and IPv6)
        return fmt.Sprintf(":%d", port)
    }
    
    // Check if it's an IPv6 address
    ip := net.ParseIP(bindAddr)
    if ip != nil && ip.To4() == nil {
        // IPv6 address - wrap in brackets
        return fmt.Sprintf("[%s]:%d", bindAddr, port)
    }
    
    // IPv4 address or hostname
    return fmt.Sprintf("%s:%d", bindAddr, port)
}
```

This ensures:
- IPv6 addresses are properly bracketed in URLs
- IPv4 addresses work as expected
- Empty bind addresses default to all interfaces
- Hostname-based binding is supported

## Benefits

1. **No More Port Conflicts:** Can run proxy and test server simultaneously
2. **IPv6 Testing:** Full support for IPv6 address testing
3. **Flexibility:** Can bind to specific interfaces for isolated testing
4. **Future-Proof:** Ready for IPv6-only environments

## Questions or Issues?

If you encounter any issues with the new port or IPv6 support, please:
1. Check if you're using the correct port (9443 for HTTPS)
2. Verify IPv6 is enabled on your system if using IPv6 binding
3. Ensure no firewall rules are blocking the new port
4. File an issue with details about your environment



