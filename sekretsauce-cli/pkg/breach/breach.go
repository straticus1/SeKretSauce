package breach

import (
	"crypto/sha1"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/straticus1/SeKretSauce/sekretsauce-cli/pkg/keychain"
)

// ScanResult contains breach detection results
type ScanResult struct {
	CheckedAt    time.Time         `json:"checked_at"`
	TotalChecked int               `json:"total_checked"`
	Compromised  []CompromisedItem `json:"compromised,omitempty"`
	Clean        int               `json:"clean"`
	Errors       []string          `json:"errors,omitempty"`
}

// CompromisedItem represents a compromised credential
type CompromisedItem struct {
	Account     string   `json:"account"`
	Service     string   `json:"service,omitempty"`
	BreachNames []string `json:"breach_names"`
	DataTypes   []string `json:"data_types,omitempty"`
	BreachDate  string   `json:"breach_date,omitempty"`
}

// HIBPBreach represents a breach from HaveIBeenPwned
type HIBPBreach struct {
	Name         string   `json:"Name"`
	Title        string   `json:"Title"`
	Domain       string   `json:"Domain"`
	BreachDate   string   `json:"BreachDate"`
	AddedDate    string   `json:"AddedDate"`
	ModifiedDate string   `json:"ModifiedDate"`
	PwnCount     int      `json:"PwnCount"`
	Description  string   `json:"Description"`
	DataClasses  []string `json:"DataClasses"`
	IsVerified   bool     `json:"IsVerified"`
	IsSensitive  bool     `json:"IsSensitive"`
}

const (
	hibpAPIBase           = "https://haveibeenpwned.com/api/v3"
	hibpPwnedPasswordsAPI = "https://api.pwnedpasswords.com"
	userAgent             = "SeKretSauce-Security-Tool"
)

// CheckEmail checks if an email has been in known breaches
func CheckEmail(email string) (*ScanResult, error) {
	result := &ScanResult{
		CheckedAt:    time.Now(),
		TotalChecked: 1,
		Compromised:  []CompromisedItem{},
		Errors:       []string{},
	}

	breaches, err := checkEmailHIBP(email)
	if err != nil {
		return nil, fmt.Errorf("HIBP check failed: %w", err)
	}

	if len(breaches) > 0 {
		comp := CompromisedItem{
			Account:     email,
			BreachNames: []string{},
			DataTypes:   []string{},
		}

		dataTypesMap := make(map[string]bool)
		for _, breach := range breaches {
			comp.BreachNames = append(comp.BreachNames, breach.Name)
			for _, dt := range breach.DataClasses {
				dataTypesMap[dt] = true
			}
			if comp.BreachDate == "" {
				comp.BreachDate = breach.BreachDate
			}
		}

		for dt := range dataTypesMap {
			comp.DataTypes = append(comp.DataTypes, dt)
		}

		result.Compromised = append(result.Compromised, comp)
	} else {
		result.Clean = 1
	}

	return result, nil
}

// CheckDomain checks for breaches associated with a domain
func CheckDomain(domain string) (*ScanResult, error) {
	result := &ScanResult{
		CheckedAt:    time.Now(),
		TotalChecked: 1,
		Compromised:  []CompromisedItem{},
		Errors:       []string{},
	}

	breaches, err := checkDomainHIBP(domain)
	if err != nil {
		return nil, fmt.Errorf("HIBP domain check failed: %w", err)
	}

	if len(breaches) > 0 {
		comp := CompromisedItem{
			Account:     domain,
			Service:     "domain",
			BreachNames: []string{},
			DataTypes:   []string{},
		}

		for _, breach := range breaches {
			comp.BreachNames = append(comp.BreachNames, breach.Name)
		}

		result.Compromised = append(result.Compromised, comp)
	} else {
		result.Clean = 1
	}

	return result, nil
}

// CheckCredentials checks keychain items against breach databases
func CheckCredentials(items []keychain.KeychainItem) (*ScanResult, error) {
	if strings.TrimSpace(os.Getenv("HIBP_API_KEY")) == "" {
		return nil, fmt.Errorf("HIBP_API_KEY is required for account breach lookups")
	}
	result := &ScanResult{
		CheckedAt:   time.Now(),
		Compromised: []CompromisedItem{},
		Errors:      []string{},
	}

	// Extract unique accounts (emails) from keychain items
	accountsChecked := make(map[string]bool)

	for _, item := range items {
		account := item.Account
		if account == "" {
			continue
		}

		// Skip if already checked
		if accountsChecked[account] {
			continue
		}

		// Only check email-like accounts to avoid excessive API calls
		if !isEmailLike(account) {
			continue
		}

		accountsChecked[account] = true
		result.TotalChecked++

		// Rate limit: HIBP has strict rate limits (1 request per 1.5 seconds for free tier)
		time.Sleep(1600 * time.Millisecond)

		breaches, err := checkEmailHIBP(account)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", account, err))
			continue
		}

		if len(breaches) > 0 {
			comp := CompromisedItem{
				Account:     account,
				Service:     item.Service,
				BreachNames: []string{},
				DataTypes:   []string{},
			}

			dataTypesMap := make(map[string]bool)
			for _, breach := range breaches {
				comp.BreachNames = append(comp.BreachNames, breach.Name)
				for _, dt := range breach.DataClasses {
					dataTypesMap[dt] = true
				}
			}

			for dt := range dataTypesMap {
				comp.DataTypes = append(comp.DataTypes, dt)
			}

			result.Compromised = append(result.Compromised, comp)
		} else {
			result.Clean++
		}
	}

	return result, nil
}

// CheckPasswordPwned checks if a password has been seen in breaches using k-anonymity
// This is safe because only the first 5 characters of the SHA-1 hash are sent to the API
func CheckPasswordPwned(password string) (bool, int, error) {
	// Hash the password
	hash := sha1.Sum([]byte(password))
	hashStr := strings.ToUpper(hex.EncodeToString(hash[:]))

	// Send only first 5 characters (k-anonymity)
	prefix := hashStr[:5]
	suffix := hashStr[5:]

	url := fmt.Sprintf("%s/range/%s", hibpPwnedPasswordsAPI, prefix)

	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return false, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, 0, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return false, 0, err
	}

	// Search for our suffix in the response
	lines := strings.Split(string(body), "\r\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 && subtle.ConstantTimeCompare([]byte(parts[0]), []byte(suffix)) == 1 {
			var count int
			fmt.Sscanf(parts[1], "%d", &count)
			return true, count, nil
		}
	}

	return false, 0, nil
}

// checkEmailHIBP checks an email against HaveIBeenPwned
func checkEmailHIBP(email string) ([]HIBPBreach, error) {
	address, err := mail.ParseAddress(email)
	if err != nil || !strings.EqualFold(address.Address, email) {
		return nil, fmt.Errorf("invalid email address")
	}
	apiKey := strings.TrimSpace(os.Getenv("HIBP_API_KEY"))
	if apiKey == "" {
		return nil, fmt.Errorf("HIBP_API_KEY is required for account breach lookups")
	}

	requestURL := fmt.Sprintf("%s/breachedaccount/%s?truncateResponse=false", hibpAPIBase, url.PathEscape(email))

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("hibp-api-key", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return []HIBPBreach{}, nil // Not found = not breached
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("HIBP API requires authentication (API key needed)")
	}

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate limited - please wait before retrying")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var breaches []HIBPBreach
	if err := json.NewDecoder(resp.Body).Decode(&breaches); err != nil {
		return nil, err
	}

	return breaches, nil
}

// checkDomainHIBP checks breaches for a domain
func checkDomainHIBP(domain string) ([]HIBPBreach, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if !validDomain(domain) {
		return nil, fmt.Errorf("invalid domain")
	}
	// Get all breaches and filter by domain
	requestURL := fmt.Sprintf("%s/breaches?domain=%s", hibpAPIBase, url.QueryEscape(domain))

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return []HIBPBreach{}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var breaches []HIBPBreach
	if err := json.NewDecoder(resp.Body).Decode(&breaches); err != nil {
		return nil, err
	}

	return breaches, nil
}

func validDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 || strings.ContainsAny(domain, "/:@?#") {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

// isEmailLike checks if a string looks like an email address
func isEmailLike(s string) bool {
	return strings.Contains(s, "@") && strings.Contains(s, ".")
}

// GetAllBreaches returns all known breaches from HIBP
func GetAllBreaches() ([]HIBPBreach, error) {
	url := fmt.Sprintf("%s/breaches", hibpAPIBase)

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var breaches []HIBPBreach
	if err := json.NewDecoder(resp.Body).Decode(&breaches); err != nil {
		return nil, err
	}

	return breaches, nil
}

// GetBreachInfo gets detailed information about a specific breach
func GetBreachInfo(name string) (*HIBPBreach, error) {
	url := fmt.Sprintf("%s/breach/%s", hibpAPIBase, name)

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("breach not found: %s", name)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var breach HIBPBreach
	if err := json.NewDecoder(resp.Body).Decode(&breach); err != nil {
		return nil, err
	}

	return &breach, nil
}
