package certs

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ScanResult contains certificate transparency results
type ScanResult struct {
	Domain       string        `json:"domain"`
	Certificates []Certificate `json:"certificates"`
	Suspicious   []Suspicious  `json:"suspicious,omitempty"`
	ScanTime     time.Time     `json:"scan_time"`
}

// Certificate represents a certificate found in CT logs
type Certificate struct {
	Issuer          string    `json:"issuer"`
	Subject         string    `json:"subject"`
	SerialNumber    string    `json:"serial_number"`
	NotBefore       time.Time `json:"not_before"`
	NotAfter        time.Time `json:"not_after"`
	SubjectAltNames []string  `json:"subject_alt_names"`
	Fingerprint     string    `json:"fingerprint"`
	LoggedAt        time.Time `json:"logged_at,omitempty"`
}

// Suspicious flags a certificate with potential issues
type Suspicious struct {
	Certificate Certificate `json:"certificate"`
	Reason      string      `json:"reason"`
	Severity    string      `json:"severity"` // "high", "medium", "low"
}

// CRTShEntry represents an entry from crt.sh
type CRTShEntry struct {
	ID             int    `json:"id"`
	IssuerCAID     int    `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	SerialNumber   string `json:"serial_number"`
	EntryTimestamp string `json:"entry_timestamp"`
}

// CheckTransparency checks certificate transparency logs for a domain
func CheckTransparency(domain string) (*ScanResult, error) {
	result := &ScanResult{
		Domain:       domain,
		Certificates: []Certificate{},
		Suspicious:   []Suspicious{},
		ScanTime:     time.Now(),
	}

	// Method 1: Query crt.sh (Certificate Transparency log aggregator)
	certs, err := queryCRTSh(domain)
	if err != nil {
		// Fall back to direct TLS inspection
		cert, err := getActiveCertificate(domain)
		if err != nil {
			return nil, fmt.Errorf("failed to get certificate info: %w", err)
		}
		result.Certificates = append(result.Certificates, *cert)
	} else {
		result.Certificates = certs
	}

	// Analyze certificates for suspicious patterns
	result.Suspicious = analyzeCertificates(result.Certificates, domain)

	return result, nil
}

// queryCRTSh queries the crt.sh certificate transparency database
func queryCRTSh(domain string) ([]Certificate, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%s&output=json", domain)

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("crt.sh query failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var entries []CRTShEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("failed to parse crt.sh response: %w", err)
	}

	// Deduplicate and convert to our Certificate struct
	seen := make(map[string]bool)
	var certs []Certificate

	for _, entry := range entries {
		if seen[entry.SerialNumber] {
			continue
		}
		seen[entry.SerialNumber] = true

		cert := Certificate{
			Issuer:       entry.IssuerName,
			Subject:      entry.CommonName,
			SerialNumber: entry.SerialNumber,
		}

		// Parse dates
		if t, err := time.Parse("2006-01-02T15:04:05", entry.NotBefore); err == nil {
			cert.NotBefore = t
		}
		if t, err := time.Parse("2006-01-02T15:04:05", entry.NotAfter); err == nil {
			cert.NotAfter = t
		}
		if t, err := time.Parse("2006-01-02T15:04:05.000", entry.EntryTimestamp); err == nil {
			cert.LoggedAt = t
		}

		// Parse SANs from name_value
		if entry.NameValue != "" {
			cert.SubjectAltNames = strings.Split(entry.NameValue, "\n")
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

// getActiveCertificate fetches the current certificate for a domain
func getActiveCertificate(domain string) (*Certificate, error) {
	conn, err := tls.Dial("tcp", domain+":443", &tls.Config{
		InsecureSkipVerify: true, // We want to see the cert even if invalid
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates returned")
	}

	x509Cert := certs[0]

	cert := &Certificate{
		Issuer:          x509Cert.Issuer.String(),
		Subject:         x509Cert.Subject.String(),
		SerialNumber:    x509Cert.SerialNumber.String(),
		NotBefore:       x509Cert.NotBefore,
		NotAfter:        x509Cert.NotAfter,
		SubjectAltNames: x509Cert.DNSNames,
		Fingerprint:     fmt.Sprintf("%x", x509Cert.Raw[:16]), // First 16 bytes as fingerprint preview
	}

	return cert, nil
}

// analyzeCertificates looks for suspicious patterns
func analyzeCertificates(certs []Certificate, domain string) []Suspicious {
	var suspicious []Suspicious

	knownSuspiciousIssuers := []string{
		"Let's Encrypt", // Not suspicious per se, but worth noting if unexpected
	}

	for _, cert := range certs {
		// Check for recently issued certificates (could indicate compromise)
		if time.Since(cert.NotBefore) < 24*time.Hour {
			suspicious = append(suspicious, Suspicious{
				Certificate: cert,
				Reason:      "Certificate issued within last 24 hours",
				Severity:    "medium",
			})
		}

		// Check for expired certificates still in logs
		if cert.NotAfter.Before(time.Now()) {
			continue // Skip expired certs for most checks
		}

		// Check for wildcard certificates
		for _, san := range cert.SubjectAltNames {
			if strings.HasPrefix(san, "*.") {
				suspicious = append(suspicious, Suspicious{
					Certificate: cert,
					Reason:      fmt.Sprintf("Wildcard certificate: %s", san),
					Severity:    "low",
				})
				break
			}
		}

		// Check for unexpected SANs (domains that don't match the target)
		for _, san := range cert.SubjectAltNames {
			cleanSAN := strings.TrimPrefix(san, "*.")
			if !strings.HasSuffix(cleanSAN, domain) && cleanSAN != domain {
				// This SAN is for a different domain - could be suspicious
				suspicious = append(suspicious, Suspicious{
					Certificate: cert,
					Reason:      fmt.Sprintf("Certificate includes unrelated domain: %s", san),
					Severity:    "high",
				})
			}
		}

		// Check for suspicious issuers (customize based on expected CAs)
		for _, issuer := range knownSuspiciousIssuers {
			if strings.Contains(cert.Issuer, issuer) {
				// Note: Let's Encrypt is legitimate but if you expect corporate certs...
				suspicious = append(suspicious, Suspicious{
					Certificate: cert,
					Reason:      fmt.Sprintf("Issued by: %s (verify if expected)", issuer),
					Severity:    "low",
				})
			}
		}

		// Check for very long validity periods (> 1 year is now unusual)
		validity := cert.NotAfter.Sub(cert.NotBefore)
		if validity > 397*24*time.Hour { // > 397 days
			suspicious = append(suspicious, Suspicious{
				Certificate: cert,
				Reason:      fmt.Sprintf("Long validity period: %d days", int(validity.Hours()/24)),
				Severity:    "low",
			})
		}
	}

	return suspicious
}

// GetCertificateChain fetches and validates the full certificate chain
func GetCertificateChain(domain string) ([]*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", domain+":443", &tls.Config{})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return conn.ConnectionState().PeerCertificates, nil
}

// ValidateCertificate performs detailed validation of a domain's certificate
func ValidateCertificate(domain string) (*ValidationResult, error) {
	result := &ValidationResult{
		Domain:  domain,
		Checks:  []ValidationCheck{},
		IsValid: true,
	}

	conn, err := tls.Dial("tcp", domain+":443", &tls.Config{})
	if err != nil {
		result.IsValid = false
		result.Checks = append(result.Checks, ValidationCheck{
			Name:    "Connection",
			Passed:  false,
			Message: err.Error(),
		})
		return result, nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	cert := state.PeerCertificates[0]

	// Check 1: Certificate is not expired
	now := time.Now()
	notExpired := now.Before(cert.NotAfter)
	result.Checks = append(result.Checks, ValidationCheck{
		Name:    "Not Expired",
		Passed:  notExpired,
		Message: fmt.Sprintf("Expires: %s", cert.NotAfter.Format(time.RFC3339)),
	})
	if !notExpired {
		result.IsValid = false
	}

	// Check 2: Certificate is valid now (not in future)
	notFuture := now.After(cert.NotBefore)
	result.Checks = append(result.Checks, ValidationCheck{
		Name:    "Valid Now",
		Passed:  notFuture,
		Message: fmt.Sprintf("Valid from: %s", cert.NotBefore.Format(time.RFC3339)),
	})
	if !notFuture {
		result.IsValid = false
	}

	// Check 3: Domain name matches
	err = cert.VerifyHostname(domain)
	nameMatches := err == nil
	msg := "Domain name matches certificate"
	if !nameMatches {
		msg = err.Error()
	}
	result.Checks = append(result.Checks, ValidationCheck{
		Name:    "Hostname Match",
		Passed:  nameMatches,
		Message: msg,
	})
	if !nameMatches {
		result.IsValid = false
	}

	// Check 4: Chain is valid
	result.Checks = append(result.Checks, ValidationCheck{
		Name:    "Chain Valid",
		Passed:  state.VerifiedChains != nil && len(state.VerifiedChains) > 0,
		Message: fmt.Sprintf("Chain length: %d", len(state.PeerCertificates)),
	})

	return result, nil
}

// ValidationResult contains the results of certificate validation
type ValidationResult struct {
	Domain  string            `json:"domain"`
	IsValid bool              `json:"is_valid"`
	Checks  []ValidationCheck `json:"checks"`
}

// ValidationCheck represents a single validation check
type ValidationCheck struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message"`
}
