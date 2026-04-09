// Package rule implements rule-based request matching using conditions, expressions, and pattern matching.
package rule

// Helper functions for equality checking

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func locationConditionsEqual(a, b *LocationConditions) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return stringSliceEqual(a.CountryCodes, b.CountryCodes) &&
		stringSliceEqual(a.Countries, b.Countries) &&
		stringSliceEqual(a.ContinentCodes, b.ContinentCodes) &&
		stringSliceEqual(a.Continents, b.Continents) &&
		stringSliceEqual(a.ASNs, b.ASNs) &&
		stringSliceEqual(a.ASNames, b.ASNames) &&
		stringSliceEqual(a.ASDomains, b.ASDomains)
}

func userAgentConditionsEqual(a, b *UserAgentConditions) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return stringSliceEqual(a.UserAgentFamilies, b.UserAgentFamilies) &&
		stringSliceEqual(a.UserAgentMajors, b.UserAgentMajors) &&
		stringSliceEqual(a.UserAgentMinors, b.UserAgentMinors) &&
		stringSliceEqual(a.OSFamilies, b.OSFamilies) &&
		stringSliceEqual(a.OSMajors, b.OSMajors) &&
		stringSliceEqual(a.OSMinors, b.OSMinors) &&
		stringSliceEqual(a.DeviceFamilies, b.DeviceFamilies) &&
		stringSliceEqual(a.DeviceBrands, b.DeviceBrands) &&
		stringSliceEqual(a.DeviceModels, b.DeviceModels)
}

