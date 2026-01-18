package keychain

import (
	"bufio"
	"bytes"
	"os/exec"
	"regexp"
	"strings"
)

// ScanOptions configures the keychain scan
type ScanOptions struct {
	Deep          bool
	IncludeSystem bool
}

// ScanResult contains keychain scan results
type ScanResult struct {
	TotalItems       int            `json:"total_items"`
	PasswordItems    int            `json:"password_items"`
	CertificateItems int            `json:"certificate_items"`
	KeyItems         int            `json:"key_items"`
	IdentityItems    int            `json:"identity_items"`
	Items            []KeychainItem `json:"items,omitempty"`
	WeakItems        []WeakItem     `json:"weak_items,omitempty"`
}

// KeychainItem represents a keychain entry (metadata only)
type KeychainItem struct {
	ItemClass   string `json:"item_class"`
	Service     string `json:"service,omitempty"`
	Account     string `json:"account,omitempty"`
	Label       string `json:"label,omitempty"`
	Server      string `json:"server,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Path        string `json:"path,omitempty"`
	Kind        string `json:"kind,omitempty"`
	Description string `json:"description,omitempty"`
}

// WeakItem flags a keychain item with potential security issues
type WeakItem struct {
	Item     KeychainItem `json:"item"`
	Reason   string       `json:"reason"`
	Severity string       `json:"severity"`
}

// Scan performs a keychain security scan using the security command
func Scan(opts ScanOptions) (*ScanResult, error) {
	result := &ScanResult{
		Items:     []KeychainItem{},
		WeakItems: []WeakItem{},
	}

	// Dump generic passwords (metadata only)
	genericItems, err := dumpKeychainItems("genp")
	if err == nil {
		for _, item := range genericItems {
			item.ItemClass = "generic_password"
			result.Items = append(result.Items, item)
			result.PasswordItems++

			// Check for weak patterns
			if weak := checkWeakItem(item); weak != nil {
				result.WeakItems = append(result.WeakItems, *weak)
			}
		}
	}

	// Dump internet passwords
	internetItems, err := dumpKeychainItems("inet")
	if err == nil {
		for _, item := range internetItems {
			item.ItemClass = "internet_password"
			result.Items = append(result.Items, item)
			result.PasswordItems++

			if weak := checkWeakItem(item); weak != nil {
				result.WeakItems = append(result.WeakItems, *weak)
			}
		}
	}

	// Dump certificates
	certItems, err := dumpKeychainItems("cert")
	if err == nil {
		for _, item := range certItems {
			item.ItemClass = "certificate"
			result.Items = append(result.Items, item)
			result.CertificateItems++
		}
	}

	// Dump keys
	keyItems, err := dumpKeychainItems("keys")
	if err == nil {
		for _, item := range keyItems {
			item.ItemClass = "key"
			result.Items = append(result.Items, item)
			result.KeyItems++
		}
	}

	// Dump identities
	idItems, err := dumpKeychainItems("idnt")
	if err == nil {
		for _, item := range idItems {
			item.ItemClass = "identity"
			result.Items = append(result.Items, item)
			result.IdentityItems++
		}
	}

	result.TotalItems = len(result.Items)

	return result, nil
}

// dumpKeychainItems uses the security command to dump keychain items
func dumpKeychainItems(itemClass string) ([]KeychainItem, error) {
	// security dump-keychain outputs item metadata (not actual passwords)
	cmd := exec.Command("security", "dump-keychain")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	return parseKeychainDump(output, itemClass), nil
}

// parseKeychainDump parses the output of security dump-keychain
func parseKeychainDump(output []byte, filterClass string) []KeychainItem {
	var items []KeychainItem
	var currentItem *KeychainItem

	scanner := bufio.NewScanner(bytes.NewReader(output))

	// Regex patterns for parsing
	classPattern := regexp.MustCompile(`class:\s*"([^"]+)"`)
	attrPattern := regexp.MustCompile(`^\s*"([^"]+)"<[^>]+>=(?:"([^"]*)")?(?:<NULL>)?(?:0x[0-9A-Fa-f]+\s+"([^"]*)")?`)
	blobPattern := regexp.MustCompile(`"([^"]+)"<blob>=`)

	for scanner.Scan() {
		line := scanner.Text()

		// Check for new keychain item
		if strings.HasPrefix(line, "keychain:") {
			if currentItem != nil {
				items = append(items, *currentItem)
			}
			currentItem = &KeychainItem{}
			continue
		}

		// Check for class
		if matches := classPattern.FindStringSubmatch(line); len(matches) > 1 {
			itemClass := matches[1]
			// Filter by requested class
			if filterClass != "" {
				if filterClass == "genp" && itemClass != "genp" {
					currentItem = nil
					continue
				}
				if filterClass == "inet" && itemClass != "inet" {
					currentItem = nil
					continue
				}
				if filterClass == "cert" && itemClass != "cert" {
					currentItem = nil
					continue
				}
				if filterClass == "keys" && itemClass != "keys" {
					currentItem = nil
					continue
				}
				if filterClass == "idnt" && itemClass != "idnt" {
					currentItem = nil
					continue
				}
			}
			if currentItem != nil {
				currentItem.ItemClass = itemClass
			}
			continue
		}

		if currentItem == nil {
			continue
		}

		// Parse attributes
		if matches := attrPattern.FindStringSubmatch(line); len(matches) > 1 {
			attrName := matches[1]
			attrValue := matches[2]
			if attrValue == "" && len(matches) > 3 {
				attrValue = matches[3]
			}

			switch attrName {
			case "svce":
				currentItem.Service = attrValue
			case "acct":
				currentItem.Account = attrValue
			case "labl":
				currentItem.Label = attrValue
			case "srvr":
				currentItem.Server = attrValue
			case "ptcl":
				currentItem.Protocol = attrValue
			case "path":
				currentItem.Path = attrValue
			case "desc":
				currentItem.Description = attrValue
			}
		}

		// Handle blob markers (we skip actual password data)
		if blobPattern.MatchString(line) {
			// This is where password data would be, but we don't extract it
			continue
		}
	}

	// Don't forget the last item
	if currentItem != nil && currentItem.ItemClass != "" {
		items = append(items, *currentItem)
	}

	return items
}

// checkWeakItem checks for security issues in a keychain item
func checkWeakItem(item KeychainItem) *WeakItem {
	// Check for HTTP (non-HTTPS) credentials
	if item.ItemClass == "internet_password" {
		if item.Protocol == "http" || item.Protocol == "htps" {
			// htps is actually HTTPS in the security command output
			if item.Protocol == "http" {
				return &WeakItem{
					Item:     item,
					Reason:   "Credential stored for HTTP (non-encrypted) connection",
					Severity: "high",
				}
			}
		}
	}

	// Check for FTP credentials
	if item.Protocol == "ftp " || item.Protocol == "ftps" {
		return &WeakItem{
			Item:     item,
			Reason:   "FTP credential (consider using SFTP)",
			Severity: "medium",
		}
	}

	// Check for common weak service patterns
	weakServices := []string{
		"com.apple.account.PasswordReset",
	}
	for _, ws := range weakServices {
		if item.Service == ws {
			return &WeakItem{
				Item:     item,
				Reason:   "Service associated with password reset - verify intentional",
				Severity: "low",
			}
		}
	}

	return nil
}

// GetItemsForService returns all keychain items for a specific service
func GetItemsForService(serviceName string) ([]KeychainItem, error) {
	result, err := Scan(ScanOptions{})
	if err != nil {
		return nil, err
	}

	var items []KeychainItem
	for _, item := range result.Items {
		if item.Service == serviceName || item.Server == serviceName {
			items = append(items, item)
		}
	}

	return items, nil
}

// FindItem finds a specific keychain item
func FindItem(service, account string) (*KeychainItem, error) {
	cmd := exec.Command("security", "find-generic-password", "-s", service, "-a", account)
	output, err := cmd.Output()
	if err != nil {
		// Try internet password
		cmd = exec.Command("security", "find-internet-password", "-s", service, "-a", account)
		output, err = cmd.Output()
		if err != nil {
			return nil, err
		}
	}

	items := parseKeychainDump(output, "")
	if len(items) > 0 {
		return &items[0], nil
	}

	return nil, nil
}

// ListKeychains returns all keychains on the system
func ListKeychains() ([]string, error) {
	cmd := exec.Command("security", "list-keychains")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var keychains []string
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		line = strings.Trim(line, "\"")
		if line != "" {
			keychains = append(keychains, line)
		}
	}

	return keychains, nil
}
