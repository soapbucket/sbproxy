// Package lua provides Lua scripting support for dynamic request/response processing.
package lua

import (
	"net"

	lua "github.com/yuin/gopher-lua"
)

// RegisterIPFunctions registers IP manipulation functions in the Lua state
func RegisterIPFunctions(L *lua.LState) {
	// Create ip table
	ipTable := L.NewTable()

	// Register ip functions
	L.SetField(ipTable, "parse", L.NewFunction(ipParse))
	L.SetField(ipTable, "in_cidr", L.NewFunction(ipInCIDR))
	L.SetField(ipTable, "is_private", L.NewFunction(ipIsPrivate))
	L.SetField(ipTable, "is_loopback", L.NewFunction(ipIsLoopback))
	L.SetField(ipTable, "is_ipv4", L.NewFunction(ipIsIPv4))
	L.SetField(ipTable, "is_ipv6", L.NewFunction(ipIsIPv6))
	L.SetField(ipTable, "in_range", L.NewFunction(ipInRange))
	L.SetField(ipTable, "compare", L.NewFunction(ipCompare))

	// Set global ip table
	L.SetGlobal("ip", ipTable)
}

// ipParse parses an IP address and returns information about it
// Usage: ip.parse("192.168.1.1")
// Returns: {valid=true, ip="192.168.1.1", is_ipv4=true, is_ipv6=false, is_private=true, is_loopback=false}
func ipParse(L *lua.LState) int {
	ipStr := L.CheckString(1)

	parsedIP := net.ParseIP(ipStr)
	result := L.NewTable()

	if parsedIP == nil {
		result.RawSetString("valid", lua.LBool(false))
		result.RawSetString("error", lua.LString("invalid IP address"))
		L.Push(result)
		return 1
	}

	result.RawSetString("valid", lua.LBool(true))
	result.RawSetString("ip", lua.LString(parsedIP.String()))
	result.RawSetString("is_ipv4", lua.LBool(parsedIP.To4() != nil))
	result.RawSetString("is_ipv6", lua.LBool(parsedIP.To4() == nil && parsedIP.To16() != nil))
	result.RawSetString("is_private", lua.LBool(isPrivateIP(parsedIP)))
	result.RawSetString("is_loopback", lua.LBool(parsedIP.IsLoopback()))

	L.Push(result)
	return 1
}

// ipInCIDR checks if an IP address is within a CIDR range
// Usage: ip.in_cidr("192.168.1.100", "192.168.1.0/24")
// Returns: boolean
func ipInCIDR(L *lua.LState) int {
	ipStr := L.CheckString(1)
	cidrStr := L.CheckString(2)

	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		L.Push(lua.LBool(false))
		return 1
	}

	_, ipNet, err := net.ParseCIDR(cidrStr)
	if err != nil {
		L.Push(lua.LBool(false))
		return 1
	}

	L.Push(lua.LBool(ipNet.Contains(parsedIP)))
	return 1
}

// ipIsPrivate checks if an IP address is in a private range
// Usage: ip.is_private("192.168.1.1")
// Returns: boolean
func ipIsPrivate(L *lua.LState) int {
	ipStr := L.CheckString(1)

	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		L.Push(lua.LBool(false))
		return 1
	}

	L.Push(lua.LBool(isPrivateIP(parsedIP)))
	return 1
}

// ipIsLoopback checks if an IP address is a loopback address
// Usage: ip.is_loopback("127.0.0.1")
// Returns: boolean
func ipIsLoopback(L *lua.LState) int {
	ipStr := L.CheckString(1)

	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		L.Push(lua.LBool(false))
		return 1
	}

	L.Push(lua.LBool(parsedIP.IsLoopback()))
	return 1
}

// ipIsIPv4 checks if an IP address is IPv4
// Usage: ip.is_ipv4("192.168.1.1")
// Returns: boolean
func ipIsIPv4(L *lua.LState) int {
	ipStr := L.CheckString(1)

	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		L.Push(lua.LBool(false))
		return 1
	}

	L.Push(lua.LBool(parsedIP.To4() != nil))
	return 1
}

// ipIsIPv6 checks if an IP address is IPv6
// Usage: ip.is_ipv6("2001:db8::1")
// Returns: boolean
func ipIsIPv6(L *lua.LState) int {
	ipStr := L.CheckString(1)

	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		L.Push(lua.LBool(false))
		return 1
	}

	// IPv6 is valid if it can be parsed and is not IPv4
	L.Push(lua.LBool(parsedIP.To4() == nil && parsedIP.To16() != nil))
	return 1
}

// ipInRange checks if an IP is between start and end IPs (inclusive)
// Usage: ip.in_range("192.168.1.100", "192.168.1.1", "192.168.1.255")
// Returns: boolean
func ipInRange(L *lua.LState) int {
	ipStr := L.CheckString(1)
	startStr := L.CheckString(2)
	endStr := L.CheckString(3)

	parsedIP := net.ParseIP(ipStr)
	if parsedIP == nil {
		L.Push(lua.LBool(false))
		return 1
	}

	start := net.ParseIP(startStr)
	if start == nil {
		L.Push(lua.LBool(false))
		return 1
	}

	end := net.ParseIP(endStr)
	if end == nil {
		L.Push(lua.LBool(false))
		return 1
	}

	// Compare IPs as bytes
	ipBytes := parsedIP.To16()
	startBytes := start.To16()
	endBytes := end.To16()

	inRange := compareIPBytes(ipBytes, startBytes) >= 0 && compareIPBytes(ipBytes, endBytes) <= 0
	L.Push(lua.LBool(inRange))
	return 1
}

// ipCompare compares two IP addresses
// Usage: ip.compare("192.168.1.1", "192.168.1.2")
// Returns: -1 if ip1 < ip2, 0 if ip1 == ip2, 1 if ip1 > ip2
func ipCompare(L *lua.LState) int {
	ip1Str := L.CheckString(1)
	ip2Str := L.CheckString(2)

	ip1 := net.ParseIP(ip1Str)
	if ip1 == nil {
		L.Push(lua.LNumber(0))
		return 1
	}

	ip2 := net.ParseIP(ip2Str)
	if ip2 == nil {
		L.Push(lua.LNumber(0))
		return 1
	}

	result := compareIPBytes(ip1.To16(), ip2.To16())
	L.Push(lua.LNumber(result))
	return 1
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
