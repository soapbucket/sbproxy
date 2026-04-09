package pii

import (
	"regexp"
	"testing"
)

func BenchmarkSeparateRegex(b *testing.B) {
	patterns := []*regexp.Regexp{
		ssnPattern,
		creditCardPattern,
		emailPattern,
		phonePatternUS,
		ipv4Pattern,
		apiKeyPattern,
		jwtPattern,
		awsKeyPattern,
	}
	body := generateTestBody(50*1024, true)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, p := range patterns {
			p.FindAllIndex(body, -1)
		}
	}
}

func BenchmarkCombinedRegex(b *testing.B) {
	combined := regexp.MustCompile(
		`(` + ssnPattern.String() + `)|` +
			`(` + creditCardPattern.String() + `)|` +
			`(` + emailPattern.String() + `)|` +
			`(` + phonePatternUS.String() + `)|` +
			`(` + ipv4Pattern.String() + `)|` +
			`(` + apiKeyPattern.String() + `)|` +
			`(` + jwtPattern.String() + `)|` +
			`(` + awsKeyPattern.String() + `)`,
	)
	body := generateTestBody(50*1024, true)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		combined.FindAllIndex(body, -1)
	}
}
