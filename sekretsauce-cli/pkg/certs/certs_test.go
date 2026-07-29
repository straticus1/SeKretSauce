package certs

import (
	"strings"
	"testing"
	"time"
)

func TestDomainValidation(t *testing.T) {
	if !validDomain("sub.example.com") {
		t.Fatal("expected valid domain")
	}
	for _, domain := range []string{"example", "https://example.com", "evil.com/path", "-bad.example"} {
		if validDomain(domain) {
			t.Fatalf("expected invalid domain: %q", domain)
		}
	}
}

func TestUnrelatedSuffixDomainIsFlagged(t *testing.T) {
	findings := analyzeCertificates([]Certificate{{
		SubjectAltNames: []string{"evil-example.com"},
		NotBefore:       time.Now().Add(-48 * time.Hour),
		NotAfter:        time.Now().Add(30 * 24 * time.Hour),
	}}, "example.com")

	if len(findings) == 0 || !strings.Contains(findings[0].Reason, "unrelated domain") {
		t.Fatalf("expected unrelated SAN finding, got %#v", findings)
	}
}

func TestSHA256FingerprintUsesAllBytes(t *testing.T) {
	fingerprint := sha256Fingerprint([]byte("certificate"))
	if len(strings.Split(fingerprint, ":")) != 32 {
		t.Fatalf("expected 32 fingerprint bytes, got %q", fingerprint)
	}
}
