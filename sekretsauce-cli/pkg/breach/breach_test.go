package breach

import "testing"

func TestValidDomainRejectsURLAndMalformedLabels(t *testing.T) {
	if !validDomain("example.com") {
		t.Fatal("expected example.com to be valid")
	}
	for _, domain := range []string{"example", "https://example.com", "-bad.example", "bad-.example", "bad/example.com"} {
		if validDomain(domain) {
			t.Fatalf("expected invalid domain: %q", domain)
		}
	}
}

func TestEmailLookupFailsClosedWithoutAPIKey(t *testing.T) {
	t.Setenv("HIBP_API_KEY", "")
	if _, err := CheckEmail("user@example.com"); err == nil {
		t.Fatal("expected missing HIBP_API_KEY to return an error")
	}
}
