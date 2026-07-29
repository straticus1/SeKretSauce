package ca

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// ScanOptions configures the CA scan
type ScanOptions struct {
	IncludeSystem  bool // Include system CA store
	IncludeUser    bool // Include user-installed CAs
	IncludeExpired bool // Include expired certificates
}

// ScanResult contains CA certificate scan results
type ScanResult struct {
	SystemCAs     []CACertificate `json:"system_cas,omitempty"`
	UserCAs       []CACertificate `json:"user_cas,omitempty"`
	SuspiciousCAs []SuspiciousCA  `json:"suspicious_cas,omitempty"`
	ExpiredCAs    []CACertificate `json:"expired_cas,omitempty"`
	Summary       CASummary       `json:"summary"`
	Platform      string          `json:"platform"`
}

// CACertificate represents a certificate authority certificate
type CACertificate struct {
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	SerialNumber  string    `json:"serial_number"`
	NotBefore     time.Time `json:"not_before"`
	NotAfter      time.Time `json:"not_after"`
	Fingerprint   string    `json:"fingerprint"`
	SignatureAlg  string    `json:"signature_algorithm"`
	KeyUsage      []string  `json:"key_usage,omitempty"`
	IsCA          bool      `json:"is_ca"`
	Source        string    `json:"source"` // system, user, keychain name
	TrustSettings []string  `json:"trust_settings,omitempty"`
	Path          string    `json:"path,omitempty"`
}

// SuspiciousCA represents a potentially suspicious CA certificate
type SuspiciousCA struct {
	Certificate CACertificate `json:"certificate"`
	Reason      string        `json:"reason"`
	Severity    string        `json:"severity"` // critical, high, medium, low
	Details     string        `json:"details,omitempty"`
}

// CASummary provides overview statistics
type CASummary struct {
	TotalCAs         int `json:"total_cas"`
	SystemCAs        int `json:"system_cas"`
	UserInstalledCAs int `json:"user_installed_cas"`
	ExpiredCAs       int `json:"expired_cas"`
	SuspiciousCAs    int `json:"suspicious_cas"`
	SelfSignedCAs    int `json:"self_signed_cas"`
	WeakAlgorithms   int `json:"weak_algorithms"`
}

// Known suspicious CA indicators
var suspiciousIndicators = []struct {
	Pattern  string
	Reason   string
	Severity string
}{
	// Known malware/adware CAs
	{Pattern: "Superfish", Reason: "Known adware CA (Superfish)", Severity: "critical"},
	{Pattern: "eDellRoot", Reason: "Known vulnerable Dell root CA", Severity: "critical"},
	{Pattern: "DSDTestProvider", Reason: "Known vulnerable Dell test CA", Severity: "critical"},
	{Pattern: "Privdog", Reason: "Known security risk CA (Privdog)", Severity: "critical"},
	{Pattern: "Komodia", Reason: "Known security risk CA (Komodia SSL Digestor)", Severity: "critical"},
	{Pattern: "Sendori", Reason: "Known adware CA", Severity: "high"},
	{Pattern: "Wajam", Reason: "Known adware CA", Severity: "high"},
	{Pattern: "Genieo", Reason: "Known adware CA", Severity: "high"},

	// Corporate MITM proxies (not necessarily bad, but worth flagging)
	{Pattern: "BlueCoat", Reason: "Corporate SSL inspection proxy", Severity: "medium"},
	{Pattern: "Zscaler", Reason: "Corporate SSL inspection proxy", Severity: "medium"},
	{Pattern: "Palo Alto", Reason: "Corporate SSL inspection proxy", Severity: "medium"},
	{Pattern: "Fortinet", Reason: "Corporate SSL inspection proxy", Severity: "medium"},
	{Pattern: "Symantec.*Proxy", Reason: "Corporate SSL inspection proxy", Severity: "medium"},
	{Pattern: "McAfee.*Gateway", Reason: "Corporate SSL inspection proxy", Severity: "medium"},
	{Pattern: "Sophos", Reason: "Corporate SSL inspection proxy", Severity: "medium"},

	// Test/Development CAs in production
	{Pattern: "(?i)test", Reason: "Test certificate in trust store", Severity: "high"},
	{Pattern: "(?i)localhost", Reason: "Localhost certificate in trust store", Severity: "high"},
	{Pattern: "(?i)development", Reason: "Development certificate in trust store", Severity: "high"},
	{Pattern: "(?i)self.?signed", Reason: "Self-signed certificate marker", Severity: "medium"},

	// Potentially compromised CAs
	{Pattern: "CNNIC", Reason: "CA with history of mis-issuance", Severity: "medium"},
	{Pattern: "WoSign", Reason: "CA with history of mis-issuance", Severity: "medium"},
	{Pattern: "StartCom", Reason: "CA with history of mis-issuance", Severity: "medium"},
}

// Weak signature algorithms
var weakAlgorithms = []string{
	"MD2", "MD4", "MD5", "SHA1",
}

// Scan performs a comprehensive CA certificate scan
func Scan(opts ScanOptions) (*ScanResult, error) {
	result := &ScanResult{
		SystemCAs:     []CACertificate{},
		UserCAs:       []CACertificate{},
		SuspiciousCAs: []SuspiciousCA{},
		ExpiredCAs:    []CACertificate{},
		Platform:      runtime.GOOS,
	}

	switch runtime.GOOS {
	case "darwin":
		if err := scanMacOSCertificates(result, opts); err != nil {
			return nil, err
		}
	case "linux":
		if err := scanLinuxCertificates(result, opts); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}

	// Analyze for suspicious certificates
	result.SuspiciousCAs = analyzeSuspiciousCAs(result.SystemCAs, result.UserCAs)

	// Filter expired
	if opts.IncludeExpired {
		result.ExpiredCAs = filterExpiredCAs(result.SystemCAs, result.UserCAs)
	}

	// Calculate summary
	result.Summary = calculateCASummary(result)

	return result, nil
}

// scanMacOSCertificates scans macOS Keychain for CA certificates
func scanMacOSCertificates(result *ScanResult, opts ScanOptions) error {
	keychains := []struct {
		path   string
		source string
		isUser bool
	}{
		{"/System/Library/Keychains/SystemRootCertificates.keychain", "System Roots", false},
		{"/Library/Keychains/System.keychain", "System", false},
	}

	// Add user keychain
	if homeDir, err := os.UserHomeDir(); err == nil {
		userKeychain := filepath.Join(homeDir, "Library/Keychains/login.keychain-db")
		keychains = append(keychains, struct {
			path   string
			source string
			isUser bool
		}{userKeychain, "User Login", true})
	}

	for _, kc := range keychains {
		if !opts.IncludeSystem && !kc.isUser {
			continue
		}
		if !opts.IncludeUser && kc.isUser {
			continue
		}

		certs, err := extractMacOSCertificates(kc.path, kc.source)
		if err != nil {
			continue
		}

		if kc.isUser {
			result.UserCAs = append(result.UserCAs, certs...)
		} else {
			result.SystemCAs = append(result.SystemCAs, certs...)
		}
	}

	return nil
}

// extractMacOSCertificates extracts certificates from a macOS keychain
func extractMacOSCertificates(keychainPath string, source string) ([]CACertificate, error) {
	var certs []CACertificate

	// Use security command to export certificates
	cmd := exec.Command("security", "find-certificate", "-a", "-p", keychainPath)
	output, err := cmd.Output()
	if err != nil {
		// Try without specific keychain (uses default search list)
		cmd = exec.Command("security", "find-certificate", "-a", "-p")
		output, err = cmd.Output()
		if err != nil {
			return nil, err
		}
	}

	// Parse PEM certificates
	rest := output
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		x509Cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		// Only include CA certificates
		if !x509Cert.IsCA && !x509Cert.BasicConstraintsValid {
			// Check if it has CA key usage even without BasicConstraints
			if x509Cert.KeyUsage&x509.KeyUsageCertSign == 0 {
				continue
			}
		}

		cert := CACertificate{
			Subject:      x509Cert.Subject.String(),
			Issuer:       x509Cert.Issuer.String(),
			SerialNumber: x509Cert.SerialNumber.String(),
			NotBefore:    x509Cert.NotBefore,
			NotAfter:     x509Cert.NotAfter,
			Fingerprint:  certificateFingerprint(x509Cert.Raw),
			SignatureAlg: x509Cert.SignatureAlgorithm.String(),
			IsCA:         x509Cert.IsCA,
			Source:       source,
			Path:         keychainPath,
		}

		// Extract key usage
		if x509Cert.KeyUsage != 0 {
			cert.KeyUsage = parseKeyUsage(x509Cert.KeyUsage)
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

func certificateFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return strings.ToUpper(hexWithColons(sum[:]))
}

func hexWithColons(value []byte) string {
	var builder strings.Builder
	for index, item := range value {
		if index > 0 {
			builder.WriteByte(':')
		}
		fmt.Fprintf(&builder, "%02X", item)
	}
	return builder.String()
}

// scanLinuxCertificates scans Linux CA certificate stores
func scanLinuxCertificates(result *ScanResult, opts ScanOptions) error {
	// Common Linux CA certificate locations
	systemPaths := []string{
		"/etc/ssl/certs",
		"/etc/pki/tls/certs",
		"/etc/pki/ca-trust/extracted/pem",
		"/usr/share/ca-certificates",
		"/usr/local/share/ca-certificates",
	}

	userPaths := []string{}
	if homeDir, err := os.UserHomeDir(); err == nil {
		userPaths = append(userPaths,
			filepath.Join(homeDir, ".local/share/ca-certificates"),
			filepath.Join(homeDir, ".pki/nssdb"),
		)
	}

	if opts.IncludeSystem {
		for _, path := range systemPaths {
			certs, err := extractLinuxCertificates(path, "System")
			if err != nil {
				continue
			}
			result.SystemCAs = append(result.SystemCAs, certs...)
		}
	}

	if opts.IncludeUser {
		for _, path := range userPaths {
			certs, err := extractLinuxCertificates(path, "User")
			if err != nil {
				continue
			}
			result.UserCAs = append(result.UserCAs, certs...)
		}
	}

	return nil
}

// extractLinuxCertificates extracts certificates from a Linux CA directory
func extractLinuxCertificates(dirPath string, source string) ([]CACertificate, error) {
	var certs []CACertificate

	info, err := os.Stat(dirPath)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		// Scan directory for certificate files
		err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}

			ext := strings.ToLower(filepath.Ext(path))
			if ext != ".pem" && ext != ".crt" && ext != ".cer" {
				return nil
			}

			fileCerts, err := parseCertificateFile(path, source)
			if err == nil {
				certs = append(certs, fileCerts...)
			}

			return nil
		})
		if err != nil {
			return nil, err
		}
	} else {
		// Single file (like ca-bundle.crt)
		certs, err = parseCertificateFile(dirPath, source)
		if err != nil {
			return nil, err
		}
	}

	return certs, nil
}

// parseCertificateFile parses a PEM certificate file
func parseCertificateFile(filePath string, source string) ([]CACertificate, error) {
	var certs []CACertificate

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		x509Cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		// Only include CA certificates
		if !x509Cert.IsCA {
			continue
		}

		cert := CACertificate{
			Subject:      x509Cert.Subject.String(),
			Issuer:       x509Cert.Issuer.String(),
			SerialNumber: x509Cert.SerialNumber.String(),
			NotBefore:    x509Cert.NotBefore,
			NotAfter:     x509Cert.NotAfter,
			Fingerprint:  fmt.Sprintf("%x", x509Cert.Raw[:16]),
			SignatureAlg: x509Cert.SignatureAlgorithm.String(),
			IsCA:         x509Cert.IsCA,
			Source:       source,
			Path:         filePath,
		}

		if x509Cert.KeyUsage != 0 {
			cert.KeyUsage = parseKeyUsage(x509Cert.KeyUsage)
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

// parseKeyUsage converts x509.KeyUsage to string slice
func parseKeyUsage(ku x509.KeyUsage) []string {
	var usages []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "DigitalSignature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "ContentCommitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "KeyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "DataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "KeyAgreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "CertSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRLSign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "EncipherOnly")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "DecipherOnly")
	}
	return usages
}

// analyzeSuspiciousCAs checks certificates against known suspicious patterns
func analyzeSuspiciousCAs(systemCAs, userCAs []CACertificate) []SuspiciousCA {
	var suspicious []SuspiciousCA

	allCAs := append(systemCAs, userCAs...)

	for _, ca := range allCAs {
		// Check against known suspicious patterns
		for _, indicator := range suspiciousIndicators {
			pattern := regexp.MustCompile(indicator.Pattern)
			if pattern.MatchString(ca.Subject) || pattern.MatchString(ca.Issuer) {
				suspicious = append(suspicious, SuspiciousCA{
					Certificate: ca,
					Reason:      indicator.Reason,
					Severity:    indicator.Severity,
				})
				break
			}
		}

		// Check for weak signature algorithms
		for _, weakAlg := range weakAlgorithms {
			if strings.Contains(ca.SignatureAlg, weakAlg) {
				suspicious = append(suspicious, SuspiciousCA{
					Certificate: ca,
					Reason:      fmt.Sprintf("Uses weak signature algorithm: %s", ca.SignatureAlg),
					Severity:    "medium",
				})
				break
			}
		}

		// Check for self-signed non-root certificates
		if ca.Subject == ca.Issuer && !strings.Contains(strings.ToLower(ca.Subject), "root") {
			suspicious = append(suspicious, SuspiciousCA{
				Certificate: ca,
				Reason:      "Self-signed certificate (not marked as root)",
				Severity:    "low",
			})
		}

		// Check for certificates expiring soon (within 30 days)
		if time.Until(ca.NotAfter) < 30*24*time.Hour && time.Until(ca.NotAfter) > 0 {
			suspicious = append(suspicious, SuspiciousCA{
				Certificate: ca,
				Reason:      "Certificate expiring soon",
				Severity:    "low",
				Details:     fmt.Sprintf("Expires: %s", ca.NotAfter.Format("2006-01-02")),
			})
		}

		// Check for certificates with very long validity (> 30 years)
		validity := ca.NotAfter.Sub(ca.NotBefore)
		if validity > 30*365*24*time.Hour {
			suspicious = append(suspicious, SuspiciousCA{
				Certificate: ca,
				Reason:      "Unusually long validity period",
				Severity:    "low",
				Details:     fmt.Sprintf("Valid for %d years", int(validity.Hours()/24/365)),
			})
		}
	}

	return suspicious
}

// filterExpiredCAs returns only expired certificates
func filterExpiredCAs(systemCAs, userCAs []CACertificate) []CACertificate {
	var expired []CACertificate

	allCAs := append(systemCAs, userCAs...)
	now := time.Now()

	for _, ca := range allCAs {
		if ca.NotAfter.Before(now) {
			expired = append(expired, ca)
		}
	}

	return expired
}

// calculateCASummary generates summary statistics
func calculateCASummary(result *ScanResult) CASummary {
	summary := CASummary{
		SystemCAs:        len(result.SystemCAs),
		UserInstalledCAs: len(result.UserCAs),
		SuspiciousCAs:    len(result.SuspiciousCAs),
		ExpiredCAs:       len(result.ExpiredCAs),
	}

	summary.TotalCAs = summary.SystemCAs + summary.UserInstalledCAs

	allCAs := append(result.SystemCAs, result.UserCAs...)
	for _, ca := range allCAs {
		// Count self-signed
		if ca.Subject == ca.Issuer {
			summary.SelfSignedCAs++
		}

		// Count weak algorithms
		for _, weakAlg := range weakAlgorithms {
			if strings.Contains(ca.SignatureAlg, weakAlg) {
				summary.WeakAlgorithms++
				break
			}
		}
	}

	return summary
}

// GetTrustSettings retrieves trust settings for a certificate on macOS
func GetTrustSettings(certPath string) ([]string, error) {
	if runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("trust settings only available on macOS")
	}

	cmd := exec.Command("security", "dump-trust-settings", "-d")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// Parse trust settings (simplified)
	var settings []string
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Trust Setting") {
			settings = append(settings, strings.TrimSpace(line))
		}
	}

	return settings, nil
}

// VerifyCertificateChain verifies a certificate chain for a given domain
func VerifyCertificateChain(domain string) (*ChainVerificationResult, error) {
	result := &ChainVerificationResult{
		Domain:       domain,
		ChainValid:   false,
		Certificates: []CACertificate{},
		Issues:       []string{},
	}

	// Use openssl to get the certificate chain
	cmd := exec.Command("openssl", "s_client", "-connect", domain+":443", "-showcerts")
	cmd.Stdin = strings.NewReader("")

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	// Parse certificates from output
	rest := output
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		x509Cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

		cert := CACertificate{
			Subject:      x509Cert.Subject.String(),
			Issuer:       x509Cert.Issuer.String(),
			SerialNumber: x509Cert.SerialNumber.String(),
			NotBefore:    x509Cert.NotBefore,
			NotAfter:     x509Cert.NotAfter,
			SignatureAlg: x509Cert.SignatureAlgorithm.String(),
			IsCA:         x509Cert.IsCA,
		}

		result.Certificates = append(result.Certificates, cert)
	}

	// Verify chain
	if len(result.Certificates) > 0 {
		result.ChainValid = true

		// Check for issues
		for i, cert := range result.Certificates {
			// Check expiration
			if cert.NotAfter.Before(time.Now()) {
				result.Issues = append(result.Issues,
					fmt.Sprintf("Certificate %d is expired", i+1))
				result.ChainValid = false
			}

			// Check not yet valid
			if cert.NotBefore.After(time.Now()) {
				result.Issues = append(result.Issues,
					fmt.Sprintf("Certificate %d is not yet valid", i+1))
				result.ChainValid = false
			}

			// Check weak algorithms
			for _, weakAlg := range weakAlgorithms {
				if strings.Contains(cert.SignatureAlg, weakAlg) {
					result.Issues = append(result.Issues,
						fmt.Sprintf("Certificate %d uses weak algorithm: %s", i+1, cert.SignatureAlg))
				}
			}
		}
	}

	return result, nil
}

// ChainVerificationResult contains certificate chain verification results
type ChainVerificationResult struct {
	Domain       string          `json:"domain"`
	ChainValid   bool            `json:"chain_valid"`
	Certificates []CACertificate `json:"certificates"`
	Issues       []string        `json:"issues,omitempty"`
}

// ListUserInstalledCAs returns only user-installed CA certificates
func ListUserInstalledCAs() ([]CACertificate, error) {
	result, err := Scan(ScanOptions{
		IncludeSystem: false,
		IncludeUser:   true,
	})
	if err != nil {
		return nil, err
	}

	return result.UserCAs, nil
}

// CheckForKnownBadCAs checks for known compromised or malicious CAs
func CheckForKnownBadCAs() ([]SuspiciousCA, error) {
	result, err := Scan(ScanOptions{
		IncludeSystem: true,
		IncludeUser:   true,
	})
	if err != nil {
		return nil, err
	}

	// Filter to only critical severity
	var badCAs []SuspiciousCA
	for _, ca := range result.SuspiciousCAs {
		if ca.Severity == "critical" || ca.Severity == "high" {
			badCAs = append(badCAs, ca)
		}
	}

	return badCAs, nil
}
