// Package cel provides Common Expression Language (CEL) evaluation for dynamic request matching and filtering.
package cel

import (
	"net"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// IPFunctions returns CEL library options for IP address manipulation functions
func IPFunctions() cel.EnvOption {
	return cel.Lib(ipLib{})
}

type ipLib struct{}

// CompileOptions performs the compile options operation on the ipLib.
func (ipLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		// ip.parse(string) -> map - Parse an IP address and return info
		cel.Function("ip.parse",
			cel.Overload("ip_parse_string",
				[]*cel.Type{cel.StringType},
				cel.MapType(cel.StringType, cel.DynType),
				cel.UnaryBinding(ipParse),
			),
		),
		// ip.inCIDR(string, string) -> bool - Check if IP is in CIDR range
		cel.Function("ip.inCIDR",
			cel.Overload("ip_in_cidr_string_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(ipInCIDR),
			),
		),
		// ip.isPrivate(string) -> bool - Check if IP is private
		cel.Function("ip.isPrivate",
			cel.Overload("ip_is_private_string",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(ipIsPrivate),
			),
		),
		// ip.isLoopback(string) -> bool - Check if IP is loopback
		cel.Function("ip.isLoopback",
			cel.Overload("ip_is_loopback_string",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(ipIsLoopback),
			),
		),
		// ip.isIPv4(string) -> bool - Check if IP is IPv4
		cel.Function("ip.isIPv4",
			cel.Overload("ip_is_ipv4_string",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(ipIsIPv4),
			),
		),
		// ip.isIPv6(string) -> bool - Check if IP is IPv6
		cel.Function("ip.isIPv6",
			cel.Overload("ip_is_ipv6_string",
				[]*cel.Type{cel.StringType},
				cel.BoolType,
				cel.UnaryBinding(ipIsIPv6),
			),
		),
		// ip.inRange(string, string, string) -> bool - Check if IP is in range
		cel.Function("ip.inRange",
			cel.Overload("ip_in_range_string_string_string",
				[]*cel.Type{cel.StringType, cel.StringType, cel.StringType},
				cel.BoolType,
				cel.FunctionBinding(ipInRange),
			),
		),
		// ip.compare(string, string) -> int - Compare two IPs (-1, 0, 1)
		cel.Function("ip.compare",
			cel.Overload("ip_compare_string_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.IntType,
				cel.BinaryBinding(ipCompare),
			),
		),
	}
}

// ProgramOptions performs the program options operation on the ipLib.
func (ipLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

// ipParse parses an IP address and returns information about it
func ipParse(val ref.Val) ref.Val {
	ipStr, ok := val.(types.String)
	if !ok {
		return types.NewErr("ip.parse requires a string argument")
	}

	ip := net.ParseIP(string(ipStr))
	if ip == nil {
		return types.NewErr("invalid IP address: %s", ipStr)
	}

	result := map[string]interface{}{
		"valid":      true,
		"ip":         ip.String(),
		"is_ipv4":    ip.To4() != nil,
		"is_ipv6":    ip.To4() == nil && ip.To16() != nil,
		"is_private": isPrivateIP(ip),
		"is_loopback": ip.IsLoopback(),
	}

	return types.DefaultTypeAdapter.NativeToValue(result)
}

// ipInCIDR checks if an IP address is within a CIDR range
func ipInCIDR(lhs, rhs ref.Val) ref.Val {
	ipStr, ok := lhs.(types.String)
	if !ok {
		return types.NewErr("ip.inCIDR first argument must be a string")
	}

	cidrStr, ok := rhs.(types.String)
	if !ok {
		return types.NewErr("ip.inCIDR second argument must be a string")
	}

	ip := net.ParseIP(string(ipStr))
	if ip == nil {
		return types.NewErr("invalid IP address: %s", ipStr)
	}

	_, ipNet, err := net.ParseCIDR(string(cidrStr))
	if err != nil {
		return types.NewErr("invalid CIDR: %s", cidrStr)
	}

	return types.Bool(ipNet.Contains(ip))
}

// ipIsPrivate checks if an IP address is private
func ipIsPrivate(val ref.Val) ref.Val {
	ipStr, ok := val.(types.String)
	if !ok {
		return types.NewErr("ip.isPrivate requires a string argument")
	}

	ip := net.ParseIP(string(ipStr))
	if ip == nil {
		return types.NewErr("invalid IP address: %s", ipStr)
	}

	return types.Bool(isPrivateIP(ip))
}

// ipIsLoopback checks if an IP address is loopback
func ipIsLoopback(val ref.Val) ref.Val {
	ipStr, ok := val.(types.String)
	if !ok {
		return types.NewErr("ip.isLoopback requires a string argument")
	}

	ip := net.ParseIP(string(ipStr))
	if ip == nil {
		return types.NewErr("invalid IP address: %s", ipStr)
	}

	return types.Bool(ip.IsLoopback())
}

// ipIsIPv4 checks if an IP address is IPv4
func ipIsIPv4(val ref.Val) ref.Val {
	ipStr, ok := val.(types.String)
	if !ok {
		return types.NewErr("ip.isIPv4 requires a string argument")
	}

	ip := net.ParseIP(string(ipStr))
	if ip == nil {
		return types.NewErr("invalid IP address: %s", ipStr)
	}

	return types.Bool(ip.To4() != nil)
}

// ipIsIPv6 checks if an IP address is IPv6
func ipIsIPv6(val ref.Val) ref.Val {
	ipStr, ok := val.(types.String)
	if !ok {
		return types.NewErr("ip.isIPv6 requires a string argument")
	}

	ip := net.ParseIP(string(ipStr))
	if ip == nil {
		return types.NewErr("invalid IP address: %s", ipStr)
	}

	// IPv6 is valid if it can be parsed and is not IPv4
	return types.Bool(ip.To4() == nil && ip.To16() != nil)
}

// ipInRange checks if an IP is between start and end IPs (inclusive)
func ipInRange(vals ...ref.Val) ref.Val {
	if len(vals) != 3 {
		return types.NewErr("ip.inRange requires exactly 3 arguments")
	}

	ipStr, ok := vals[0].(types.String)
	if !ok {
		return types.NewErr("ip.inRange first argument must be a string")
	}

	startStr, ok := vals[1].(types.String)
	if !ok {
		return types.NewErr("ip.inRange second argument must be a string")
	}

	endStr, ok := vals[2].(types.String)
	if !ok {
		return types.NewErr("ip.inRange third argument must be a string")
	}

	ip := net.ParseIP(string(ipStr))
	if ip == nil {
		return types.NewErr("invalid IP address: %s", ipStr)
	}

	start := net.ParseIP(string(startStr))
	if start == nil {
		return types.NewErr("invalid start IP address: %s", startStr)
	}

	end := net.ParseIP(string(endStr))
	if end == nil {
		return types.NewErr("invalid end IP address: %s", endStr)
	}

	// Compare IPs as bytes
	ipBytes := ip.To16()
	startBytes := start.To16()
	endBytes := end.To16()

	inRange := compareIPBytes(ipBytes, startBytes) >= 0 && compareIPBytes(ipBytes, endBytes) <= 0
	return types.Bool(inRange)
}

// ipCompare compares two IP addresses
// Returns -1 if ip1 < ip2, 0 if ip1 == ip2, 1 if ip1 > ip2
func ipCompare(lhs, rhs ref.Val) ref.Val {
	ip1Str, ok := lhs.(types.String)
	if !ok {
		return types.NewErr("ip.compare first argument must be a string")
	}

	ip2Str, ok := rhs.(types.String)
	if !ok {
		return types.NewErr("ip.compare second argument must be a string")
	}

	ip1 := net.ParseIP(string(ip1Str))
	if ip1 == nil {
		return types.NewErr("invalid IP address: %s", ip1Str)
	}

	ip2 := net.ParseIP(string(ip2Str))
	if ip2 == nil {
		return types.NewErr("invalid IP address: %s", ip2Str)
	}

	result := compareIPBytes(ip1.To16(), ip2.To16())
	return types.Int(result)
}

// isPrivateIP checks if an IP address is in a private range
func isPrivateIP(ip net.IP) bool {
	if ip.IsLoopback() {
		return true
	}

	// Check IPv4 private ranges
	if ip4 := ip.To4(); ip4 != nil {
		// 10.0.0.0/8
		if ip4[0] == 10 {
			return true
		}
		// 172.16.0.0/12
		if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
			return true
		}
		// 192.168.0.0/16
		if ip4[0] == 192 && ip4[1] == 168 {
			return true
		}
		// 169.254.0.0/16 (link-local)
		if ip4[0] == 169 && ip4[1] == 254 {
			return true
		}
		return false
	}

	// Check IPv6 private ranges
	if ip.To16() != nil {
		// fc00::/7 (Unique Local Address)
		if ip[0] == 0xfc || ip[0] == 0xfd {
			return true
		}
		// fe80::/10 (Link-local)
		if ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 {
			return true
		}
	}

	return false
}

// compareIPBytes compares two IP addresses as byte slices
func compareIPBytes(ip1, ip2 []byte) int {
	for i := 0; i < len(ip1) && i < len(ip2); i++ {
		if ip1[i] < ip2[i] {
			return -1
		}
		if ip1[i] > ip2[i] {
			return 1
		}
	}
	return 0
}

// getClientIP extracts the client IP from the request
// It checks X-Real-IP, X-Forwarded-For, and RemoteAddr in that order
func getClientIP(remoteAddr string, headers map[string]string) string {
	// Check X-Real-IP header first (highest precedence)
	// Note: headers are normalized to lowercase (e.g. "x-real-ip")
	if xri := headers["x-real-ip"]; xri != "" {
		return strings.TrimSpace(xri)
	}

	// Check X-Forwarded-For header (first IP in the list)
	if xff := headers["x-forwarded-for"]; xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Use RemoteAddr (extract IP from "host:port" format)
	if remoteAddr != "" {
		host, _, err := net.SplitHostPort(remoteAddr)
		if err == nil {
			return host
		}
		// If SplitHostPort fails, try to use RemoteAddr as-is (might be just IP)
		return remoteAddr
	}

	return ""
}

