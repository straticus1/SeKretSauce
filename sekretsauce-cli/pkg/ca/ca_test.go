package ca

import (
	"strings"
	"testing"
)

func TestCertificateFingerprintIsFullSHA256(t *testing.T) {
	fingerprint := certificateFingerprint([]byte("certificate"))
	if len(strings.Split(fingerprint, ":")) != 32 {
		t.Fatalf("expected 32 fingerprint bytes, got %q", fingerprint)
	}
}
