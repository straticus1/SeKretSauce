package secrets

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// ScanOptions configures the secrets scan
type ScanOptions struct {
	Paths       []string // Directories to scan
	MaxFileSize int64    // Max file size to scan (default 1MB)
	MaxDepth    int      // Max directory depth (0 = unlimited)
	IncludeGit  bool     // Include .git directories
	Concurrent  int      // Number of concurrent scanners
}

// ScanResult contains secrets scan results
type ScanResult struct {
	TotalFilesScanned int            `json:"total_files_scanned"`
	SecretsFound      []Secret       `json:"secrets_found,omitempty"`
	PasswordFiles     []PasswordFile `json:"password_files,omitempty"`
	EnvFiles          []EnvFile      `json:"env_files,omitempty"`
	Summary           SecretsSummary `json:"summary"`
}

// Secret represents a detected secret
type Secret struct {
	Type       string `json:"type"`
	File       string `json:"file"`
	Line       int    `json:"line"`
	Match      string `json:"match"`   // Redacted match
	Context    string `json:"context"` // Surrounding context (redacted)
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"` // high, medium, low
}

// PasswordFile represents a file likely containing passwords
type PasswordFile struct {
	Path        string   `json:"path"`
	Type        string   `json:"type"` // .env, config, etc.
	Indicators  []string `json:"indicators"`
	Permissions string   `json:"permissions"`
	Severity    string   `json:"severity"`
}

// EnvFile represents a .env or similar configuration file
type EnvFile struct {
	Path       string   `json:"path"`
	Variables  []string `json:"variables"` // Variable names only, not values
	HasSecrets bool     `json:"has_secrets"`
}

// SecretsSummary provides overview statistics
type SecretsSummary struct {
	APIKeys           int `json:"api_keys"`
	PrivateKeys       int `json:"private_keys"`
	Passwords         int `json:"passwords"`
	Tokens            int `json:"tokens"`
	ConnectionStrings int `json:"connection_strings"`
	CriticalFindings  int `json:"critical_findings"`
}

// SecretPattern defines a pattern to search for
type SecretPattern struct {
	Name       string
	Pattern    *regexp.Regexp
	Type       string
	Severity   string
	Confidence string
}

// Common secret patterns
var secretPatterns = []SecretPattern{
	// AWS
	{Name: "AWS Access Key ID", Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Type: "aws_access_key", Severity: "critical", Confidence: "high"},
	{Name: "AWS Secret Access Key", Pattern: regexp.MustCompile(`(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]`), Type: "aws_secret", Severity: "critical", Confidence: "medium"},

	// GCP
	{Name: "GCP API Key", Pattern: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), Type: "gcp_api_key", Severity: "critical", Confidence: "high"},
	{Name: "GCP Service Account", Pattern: regexp.MustCompile(`"type"\s*:\s*"service_account"`), Type: "gcp_service_account", Severity: "critical", Confidence: "high"},

	// Azure
	{Name: "Azure Storage Key", Pattern: regexp.MustCompile(`(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}`), Type: "azure_storage", Severity: "critical", Confidence: "high"},

	// GitHub
	{Name: "GitHub Token", Pattern: regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`), Type: "github_token", Severity: "critical", Confidence: "high"},
	{Name: "GitHub Token (old)", Pattern: regexp.MustCompile(`github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}`), Type: "github_pat", Severity: "critical", Confidence: "high"},
	{Name: "GitHub OAuth", Pattern: regexp.MustCompile(`gho_[0-9a-zA-Z]{36}`), Type: "github_oauth", Severity: "critical", Confidence: "high"},

	// Slack
	{Name: "Slack Token", Pattern: regexp.MustCompile(`xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`), Type: "slack_token", Severity: "critical", Confidence: "high"},
	{Name: "Slack Webhook", Pattern: regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+`), Type: "slack_webhook", Severity: "high", Confidence: "high"},

	// Stripe
	{Name: "Stripe Secret Key", Pattern: regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,}`), Type: "stripe_secret", Severity: "critical", Confidence: "high"},
	{Name: "Stripe Publishable Key", Pattern: regexp.MustCompile(`pk_live_[0-9a-zA-Z]{24,}`), Type: "stripe_publishable", Severity: "medium", Confidence: "high"},

	// Twilio
	{Name: "Twilio API Key", Pattern: regexp.MustCompile(`SK[0-9a-fA-F]{32}`), Type: "twilio_api", Severity: "critical", Confidence: "medium"},

	// SendGrid
	{Name: "SendGrid API Key", Pattern: regexp.MustCompile(`SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}`), Type: "sendgrid_api", Severity: "critical", Confidence: "high"},

	// Mailchimp
	{Name: "Mailchimp API Key", Pattern: regexp.MustCompile(`[0-9a-f]{32}-us[0-9]{1,2}`), Type: "mailchimp_api", Severity: "high", Confidence: "medium"},

	// Private Keys
	{Name: "RSA Private Key", Pattern: regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`), Type: "rsa_private_key", Severity: "critical", Confidence: "high"},             // gitleaks:allow -- detector signature, not key material
	{Name: "OpenSSH Private Key", Pattern: regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`), Type: "openssh_private_key", Severity: "critical", Confidence: "high"}, // gitleaks:allow -- detector signature, not key material
	{Name: "DSA Private Key", Pattern: regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----`), Type: "dsa_private_key", Severity: "critical", Confidence: "high"},             // gitleaks:allow -- detector signature, not key material
	{Name: "EC Private Key", Pattern: regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`), Type: "ec_private_key", Severity: "critical", Confidence: "high"},                // gitleaks:allow -- detector signature, not key material
	{Name: "PGP Private Key", Pattern: regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`), Type: "pgp_private_key", Severity: "critical", Confidence: "high"},       // gitleaks:allow -- detector signature, not key material

	// Database Connection Strings
	{Name: "PostgreSQL URI", Pattern: regexp.MustCompile(`postgres(ql)?://[^:]+:[^@]+@[^/]+/[^\s]+`), Type: "postgres_uri", Severity: "critical", Confidence: "high"},
	{Name: "MySQL URI", Pattern: regexp.MustCompile(`mysql://[^:]+:[^@]+@[^/]+/[^\s]+`), Type: "mysql_uri", Severity: "critical", Confidence: "high"},
	{Name: "MongoDB URI", Pattern: regexp.MustCompile(`mongodb(\+srv)?://[^:]+:[^@]+@[^\s]+`), Type: "mongodb_uri", Severity: "critical", Confidence: "high"},
	{Name: "Redis URI", Pattern: regexp.MustCompile(`redis://[^:]*:[^@]+@[^\s]+`), Type: "redis_uri", Severity: "critical", Confidence: "high"},

	// JWT
	{Name: "JWT Token", Pattern: regexp.MustCompile(`eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+`), Type: "jwt_token", Severity: "high", Confidence: "high"},

	// Generic Secrets
	{Name: "Generic API Key", Pattern: regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"]?[0-9a-zA-Z]{20,}['\"]?`), Type: "generic_api_key", Severity: "high", Confidence: "medium"},
	{Name: "Generic Secret", Pattern: regexp.MustCompile(`(?i)(secret|password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]`), Type: "generic_secret", Severity: "high", Confidence: "medium"},
	{Name: "Bearer Token", Pattern: regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+`), Type: "bearer_token", Severity: "high", Confidence: "medium"},

	// Heroku
	{Name: "Heroku API Key", Pattern: regexp.MustCompile(`(?i)heroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`), Type: "heroku_api", Severity: "critical", Confidence: "medium"},

	// NPM
	{Name: "NPM Token", Pattern: regexp.MustCompile(`//registry\.npmjs\.org/:_authToken=[0-9a-f-]+`), Type: "npm_token", Severity: "critical", Confidence: "high"},

	// PyPI
	{Name: "PyPI Token", Pattern: regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}`), Type: "pypi_token", Severity: "critical", Confidence: "high"},

	// Discord
	{Name: "Discord Token", Pattern: regexp.MustCompile(`[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}`), Type: "discord_token", Severity: "critical", Confidence: "high"},
	{Name: "Discord Webhook", Pattern: regexp.MustCompile(`https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+`), Type: "discord_webhook", Severity: "high", Confidence: "high"},

	// Telegram
	{Name: "Telegram Bot Token", Pattern: regexp.MustCompile(`[0-9]+:AA[0-9A-Za-z\-_]{33}`), Type: "telegram_bot", Severity: "high", Confidence: "high"},

	// OpenAI
	{Name: "OpenAI API Key", Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{48}`), Type: "openai_api", Severity: "critical", Confidence: "high"},

	// Anthropic
	{Name: "Anthropic API Key", Pattern: regexp.MustCompile(`sk-ant-api[0-9]{2}-[A-Za-z0-9\-_]{93}`), Type: "anthropic_api", Severity: "critical", Confidence: "high"},

	// Datadog
	{Name: "Datadog API Key", Pattern: regexp.MustCompile(`(?i)datadog.*['\"][a-f0-9]{32}['\"]`), Type: "datadog_api", Severity: "high", Confidence: "medium"},
}

// Password file patterns
var passwordFilePatterns = []struct {
	Pattern  string
	Type     string
	Severity string
}{
	{".env", "env_file", "high"},
	{".env.local", "env_file", "high"},
	{".env.production", "env_file", "critical"},
	{".env.development", "env_file", "high"},
	{"credentials", "credentials_file", "critical"},
	{"credentials.json", "credentials_file", "critical"},
	{"secrets.json", "secrets_file", "critical"},
	{"secrets.yaml", "secrets_file", "critical"},
	{"secrets.yml", "secrets_file", "critical"},
	{".htpasswd", "htpasswd", "critical"},
	{".pgpass", "pgpass", "critical"},
	{".netrc", "netrc", "critical"},
	{".npmrc", "npmrc", "high"},
	{".pypirc", "pypirc", "high"},
	{"wp-config.php", "wordpress_config", "critical"},
	{"database.yml", "rails_database", "critical"},
	{"config.php", "php_config", "high"},
	{"settings.py", "django_settings", "high"},
	{"application.properties", "java_properties", "high"},
	{"application.yml", "java_properties", "high"},
	{".docker/config.json", "docker_config", "high"},
	{"id_rsa", "ssh_key", "critical"},
	{"id_dsa", "ssh_key", "critical"},
	{"id_ecdsa", "ssh_key", "critical"},
	{"id_ed25519", "ssh_key", "critical"},
}

// Scan performs a comprehensive secrets scan
func Scan(opts ScanOptions) (*ScanResult, error) {
	if opts.MaxFileSize == 0 {
		opts.MaxFileSize = 1024 * 1024 // 1MB default
	}
	if opts.Concurrent == 0 {
		opts.Concurrent = 4
	}
	if len(opts.Paths) == 0 {
		opts.Paths = []string{"."}
	}

	result := &ScanResult{
		SecretsFound:  []Secret{},
		PasswordFiles: []PasswordFile{},
		EnvFiles:      []EnvFile{},
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	fileChan := make(chan string, 100)

	// Start worker goroutines
	for i := 0; i < opts.Concurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for filePath := range fileChan {
				secrets, pwFile, envFile := scanFile(filePath, opts.MaxFileSize)

				mu.Lock()
				result.TotalFilesScanned++
				result.SecretsFound = append(result.SecretsFound, secrets...)
				if pwFile != nil {
					result.PasswordFiles = append(result.PasswordFiles, *pwFile)
				}
				if envFile != nil {
					result.EnvFiles = append(result.EnvFiles, *envFile)
				}
				mu.Unlock()
			}
		}()
	}

	// Walk directories and send files to workers
	for _, basePath := range opts.Paths {
		filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			// Skip directories
			if info.IsDir() {
				// Skip .git unless requested
				if !opts.IncludeGit && info.Name() == ".git" {
					return filepath.SkipDir
				}
				// Skip common non-useful directories
				skipDirs := []string{"node_modules", "vendor", ".venv", "__pycache__", "dist", "build"}
				for _, skip := range skipDirs {
					if info.Name() == skip {
						return filepath.SkipDir
					}
				}
				return nil
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return nil
			}

			// Skip files that are too large
			if info.Size() > opts.MaxFileSize {
				return nil
			}

			// Skip binary files (basic check)
			if isBinaryFile(path) {
				return nil
			}

			fileChan <- path
			return nil
		})
	}

	close(fileChan)
	wg.Wait()

	// Calculate summary
	result.Summary = calculateSummary(result)

	return result, nil
}

// scanFile scans a single file for secrets
func scanFile(filePath string, maxSize int64) ([]Secret, *PasswordFile, *EnvFile) {
	var secrets []Secret
	var pwFile *PasswordFile
	var envFile *EnvFile

	// Check if this is a known password file type
	fileName := filepath.Base(filePath)
	for _, pf := range passwordFilePatterns {
		if strings.EqualFold(fileName, pf.Pattern) || strings.HasSuffix(filePath, pf.Pattern) {
			info, _ := os.Stat(filePath)
			pwFile = &PasswordFile{
				Path:       filePath,
				Type:       pf.Type,
				Indicators: []string{pf.Pattern},
				Severity:   pf.Severity,
			}
			if info != nil {
				pwFile.Permissions = info.Mode().String()
			}
			break
		}
	}

	// Check if this is an env file
	if strings.HasPrefix(fileName, ".env") || fileName == "env" {
		envFile = parseEnvFile(filePath)
	}

	// Scan file content for secrets
	file, err := os.Open(filePath)
	if err != nil {
		return secrets, pwFile, envFile
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Check each pattern
		for _, pattern := range secretPatterns {
			if matches := pattern.Pattern.FindAllString(line, -1); matches != nil {
				for _, match := range matches {
					secrets = append(secrets, Secret{
						Type:       pattern.Type,
						File:       filePath,
						Line:       lineNum,
						Match:      redactSecret(match),
						Context:    redactLine(line),
						Severity:   pattern.Severity,
						Confidence: pattern.Confidence,
					})
				}
			}
		}
	}

	return secrets, pwFile, envFile
}

// parseEnvFile extracts variable names from an env file
func parseEnvFile(filePath string) *EnvFile {
	envFile := &EnvFile{
		Path:      filePath,
		Variables: []string{},
	}

	file, err := os.Open(filePath)
	if err != nil {
		return envFile
	}
	defer file.Close()

	sensitivePatterns := []string{
		"password", "secret", "key", "token", "api", "auth",
		"credential", "private", "access", "bearer",
	}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) >= 1 {
			varName := strings.TrimSpace(parts[0])
			envFile.Variables = append(envFile.Variables, varName)

			// Check if variable name suggests sensitive data
			lowerVar := strings.ToLower(varName)
			for _, pattern := range sensitivePatterns {
				if strings.Contains(lowerVar, pattern) {
					envFile.HasSecrets = true
					break
				}
			}
		}
	}

	return envFile
}

// redactSecret partially redacts a secret value
func redactSecret(secret string) string {
	if len(secret) <= 8 {
		return "***REDACTED***"
	}
	// Show first 4 and last 4 characters
	return secret[:4] + "..." + secret[len(secret)-4:] + " (redacted)"
}

// redactLine redacts potentially sensitive parts of a line
func redactLine(line string) string {
	if len(line) > 100 {
		line = line[:100] + "..."
	}
	// Redact anything after = or : that looks like a value
	patterns := []string{
		`(=\s*)[^\s]+`,
		`(:\s*)[^\s]+`,
	}
	for _, p := range patterns {
		re := regexp.MustCompile(p)
		line = re.ReplaceAllString(line, "$1***REDACTED***")
	}
	return line
}

// isBinaryFile checks if a file is likely binary
func isBinaryFile(path string) bool {
	binaryExtensions := []string{
		".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a",
		".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp",
		".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv",
		".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
		".pdf", ".doc", ".docx", ".xls", ".xlsx",
		".woff", ".woff2", ".ttf", ".eot",
		".pyc", ".class", ".jar",
	}

	ext := strings.ToLower(filepath.Ext(path))
	for _, binExt := range binaryExtensions {
		if ext == binExt {
			return true
		}
	}

	return false
}

// calculateSummary generates summary statistics
func calculateSummary(result *ScanResult) SecretsSummary {
	summary := SecretsSummary{}

	for _, secret := range result.SecretsFound {
		switch {
		case strings.Contains(secret.Type, "api"):
			summary.APIKeys++
		case strings.Contains(secret.Type, "private_key"):
			summary.PrivateKeys++
		case strings.Contains(secret.Type, "password") || strings.Contains(secret.Type, "secret"):
			summary.Passwords++
		case strings.Contains(secret.Type, "token"):
			summary.Tokens++
		case strings.Contains(secret.Type, "uri") || strings.Contains(secret.Type, "connection"):
			summary.ConnectionStrings++
		}

		if secret.Severity == "critical" {
			summary.CriticalFindings++
		}
	}

	// Add password files to critical count
	for _, pf := range result.PasswordFiles {
		if pf.Severity == "critical" {
			summary.CriticalFindings++
		}
	}

	return summary
}

// ScanDirectory is a convenience function to scan a single directory
func ScanDirectory(path string) (*ScanResult, error) {
	return Scan(ScanOptions{
		Paths: []string{path},
	})
}

// ScanHomeDirectory scans common locations in user's home directory
func ScanHomeDirectory() (*ScanResult, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	paths := []string{
		homeDir,
		filepath.Join(homeDir, "Documents"),
		filepath.Join(homeDir, "Desktop"),
		filepath.Join(homeDir, "Downloads"),
		filepath.Join(homeDir, ".ssh"),
		filepath.Join(homeDir, ".aws"),
		filepath.Join(homeDir, ".config"),
	}

	// Filter to existing paths
	var existingPaths []string
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			existingPaths = append(existingPaths, p)
		}
	}

	return Scan(ScanOptions{
		Paths:    existingPaths,
		MaxDepth: 3, // Don't go too deep from home
	})
}
