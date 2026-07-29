package wallet

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// ScanOptions configures the wallet scan
type ScanOptions struct {
	Paths      []string // Additional paths to scan
	ScanHome   bool     // Scan user's home directory
	ScanCommon bool     // Scan common wallet locations
	Deep       bool     // Deep scan (slower, more thorough)
}

// ScanResult contains wallet scan results
type ScanResult struct {
	WalletsFound     []Wallet      `json:"wallets_found,omitempty"`
	WalletFiles      []WalletFile  `json:"wallet_files,omitempty"`
	SeedPhrases      []SeedPhrase  `json:"seed_phrases,omitempty"`
	AddressesInFiles []AddressFind `json:"addresses_in_files,omitempty"`
	Summary          WalletSummary `json:"summary"`
}

// Wallet represents a found cryptocurrency wallet
type Wallet struct {
	Type        string `json:"type"`        // bitcoin, ethereum, etc.
	Application string `json:"application"` // Bitcoin Core, MetaMask, etc.
	Path        string `json:"path"`
	Encrypted   bool   `json:"encrypted"`
	Size        int64  `json:"size"`
	Modified    string `json:"modified"`
	Risk        string `json:"risk"` // critical, high, medium, low
}

// WalletFile represents a file that may contain wallet data
type WalletFile struct {
	Path        string `json:"path"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Risk        string `json:"risk"`
}

// SeedPhrase represents a potential seed phrase/mnemonic found
type SeedPhrase struct {
	File      string `json:"file"`
	Line      int    `json:"line"`
	WordCount int    `json:"word_count"`
	Redacted  string `json:"redacted"` // First word + count
	Risk      string `json:"risk"`
}

// AddressFind represents a crypto address found in a file
type AddressFind struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Type    string `json:"type"`    // bitcoin, ethereum, etc.
	Address string `json:"address"` // Partially redacted
}

// WalletSummary provides overview statistics
type WalletSummary struct {
	TotalWallets     int `json:"total_wallets"`
	BitcoinWallets   int `json:"bitcoin_wallets"`
	EthereumWallets  int `json:"ethereum_wallets"`
	OtherWallets     int `json:"other_wallets"`
	SeedPhrasesFound int `json:"seed_phrases_found"`
	CriticalFindings int `json:"critical_findings"`
}

// WalletLocation defines where to look for wallet files
type WalletLocation struct {
	Name        string
	Type        string
	RelPath     string // Relative to home directory
	AbsPath     string // Absolute path
	Pattern     string // File pattern to match
	Description string
	Risk        string
}

// Common wallet locations by platform
var walletLocations = []WalletLocation{
	// Bitcoin Core
	{Name: "Bitcoin Core", Type: "bitcoin", RelPath: "Library/Application Support/Bitcoin/wallet.dat", Description: "Bitcoin Core wallet file", Risk: "critical"},
	{Name: "Bitcoin Core", Type: "bitcoin", RelPath: ".bitcoin/wallet.dat", Description: "Bitcoin Core wallet file (Linux)", Risk: "critical"},
	{Name: "Bitcoin Core", Type: "bitcoin", RelPath: "AppData/Roaming/Bitcoin/wallet.dat", Description: "Bitcoin Core wallet file (Windows)", Risk: "critical"},

	// Electrum
	{Name: "Electrum", Type: "bitcoin", RelPath: ".electrum/wallets", Description: "Electrum wallet directory", Risk: "critical"},
	{Name: "Electrum", Type: "bitcoin", RelPath: "Library/Application Support/Electrum/wallets", Description: "Electrum wallet directory (macOS)", Risk: "critical"},

	// Ethereum - Geth
	{Name: "Geth", Type: "ethereum", RelPath: ".ethereum/keystore", Description: "Geth keystore directory", Risk: "critical"},
	{Name: "Geth", Type: "ethereum", RelPath: "Library/Ethereum/keystore", Description: "Geth keystore directory (macOS)", Risk: "critical"},

	// MetaMask (browser extension data)
	{Name: "MetaMask Chrome", Type: "ethereum", RelPath: "Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn", Description: "MetaMask Chrome extension data", Risk: "critical"},
	{Name: "MetaMask Firefox", Type: "ethereum", RelPath: "Library/Application Support/Firefox/Profiles", Pattern: "*/storage/default/moz-extension*/idb", Description: "MetaMask Firefox extension data", Risk: "critical"},

	// Exodus
	{Name: "Exodus", Type: "multi", RelPath: "Library/Application Support/Exodus/exodus.wallet", Description: "Exodus wallet data", Risk: "critical"},
	{Name: "Exodus", Type: "multi", RelPath: ".config/Exodus/exodus.wallet", Description: "Exodus wallet data (Linux)", Risk: "critical"},

	// Atomic Wallet
	{Name: "Atomic Wallet", Type: "multi", RelPath: "Library/Application Support/atomic/Local Storage", Description: "Atomic Wallet data", Risk: "critical"},

	// Ledger Live
	{Name: "Ledger Live", Type: "multi", RelPath: "Library/Application Support/Ledger Live", Description: "Ledger Live application data", Risk: "high"},

	// Trust Wallet
	{Name: "Trust Wallet", Type: "multi", RelPath: "Library/Application Support/Trust Wallet", Description: "Trust Wallet data", Risk: "critical"},

	// Litecoin
	{Name: "Litecoin Core", Type: "litecoin", RelPath: "Library/Application Support/Litecoin/wallet.dat", Description: "Litecoin Core wallet", Risk: "critical"},
	{Name: "Litecoin Core", Type: "litecoin", RelPath: ".litecoin/wallet.dat", Description: "Litecoin Core wallet (Linux)", Risk: "critical"},

	// Monero
	{Name: "Monero", Type: "monero", RelPath: ".bitmonero/wallets", Description: "Monero wallet directory", Risk: "critical"},
	{Name: "Monero GUI", Type: "monero", RelPath: "Library/Application Support/monero-wallet-gui/wallets", Description: "Monero GUI wallets", Risk: "critical"},

	// Dogecoin
	{Name: "Dogecoin Core", Type: "dogecoin", RelPath: "Library/Application Support/Dogecoin/wallet.dat", Description: "Dogecoin Core wallet", Risk: "critical"},
	{Name: "Dogecoin Core", Type: "dogecoin", RelPath: ".dogecoin/wallet.dat", Description: "Dogecoin Core wallet (Linux)", Risk: "critical"},

	// Solana
	{Name: "Solana CLI", Type: "solana", RelPath: ".config/solana/id.json", Description: "Solana CLI keypair", Risk: "critical"},

	// Cardano
	{Name: "Daedalus", Type: "cardano", RelPath: "Library/Application Support/Daedalus Mainnet/wallets", Description: "Daedalus wallet", Risk: "critical"},
}

// Crypto address patterns
var addressPatterns = []struct {
	Name    string
	Pattern *regexp.Regexp
	Type    string
}{
	// Bitcoin (Legacy, SegWit, Native SegWit)
	{Name: "Bitcoin Legacy", Pattern: regexp.MustCompile(`\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b`), Type: "bitcoin"},
	{Name: "Bitcoin SegWit", Pattern: regexp.MustCompile(`\b3[a-km-zA-HJ-NP-Z1-9]{25,34}\b`), Type: "bitcoin"},
	{Name: "Bitcoin Bech32", Pattern: regexp.MustCompile(`\bbc1[a-z0-9]{39,59}\b`), Type: "bitcoin"},

	// Ethereum and EVM chains
	{Name: "Ethereum", Pattern: regexp.MustCompile(`\b0x[a-fA-F0-9]{40}\b`), Type: "ethereum"},

	// Litecoin
	{Name: "Litecoin Legacy", Pattern: regexp.MustCompile(`\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b`), Type: "litecoin"},
	{Name: "Litecoin Bech32", Pattern: regexp.MustCompile(`\bltc1[a-z0-9]{39,59}\b`), Type: "litecoin"},

	// Dogecoin
	{Name: "Dogecoin", Pattern: regexp.MustCompile(`\bD{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}\b`), Type: "dogecoin"},

	// Monero
	{Name: "Monero", Pattern: regexp.MustCompile(`\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b`), Type: "monero"},

	// Solana
	{Name: "Solana", Pattern: regexp.MustCompile(`\b[1-9A-HJ-NP-Za-km-z]{32,44}\b`), Type: "solana"},

	// Cardano
	{Name: "Cardano", Pattern: regexp.MustCompile(`\baddr1[a-z0-9]{58}\b`), Type: "cardano"},

	// Ripple
	{Name: "Ripple", Pattern: regexp.MustCompile(`\br[0-9a-zA-Z]{24,34}\b`), Type: "ripple"},

	// Tron
	{Name: "Tron", Pattern: regexp.MustCompile(`\bT[A-Za-z1-9]{33}\b`), Type: "tron"},
}

// BIP39 word list check (first 100 words for quick validation)
var bip39SampleWords = map[string]bool{
	"abandon": true, "ability": true, "able": true, "about": true, "above": true,
	"absent": true, "absorb": true, "abstract": true, "absurd": true, "abuse": true,
	"access": true, "accident": true, "account": true, "accuse": true, "achieve": true,
	"acid": true, "acoustic": true, "acquire": true, "across": true, "act": true,
	"action": true, "actor": true, "actress": true, "actual": true, "adapt": true,
	"add": true, "addict": true, "address": true, "adjust": true, "admit": true,
	"adult": true, "advance": true, "advice": true, "aerobic": true, "affair": true,
	"afford": true, "afraid": true, "again": true, "age": true, "agent": true,
	"agree": true, "ahead": true, "aim": true, "air": true, "airport": true,
	"aisle": true, "alarm": true, "album": true, "alcohol": true, "alert": true,
	"alien": true, "all": true, "alley": true, "allow": true, "almost": true,
	"alone": true, "alpha": true, "already": true, "also": true, "alter": true,
	"always": true, "amateur": true, "amazing": true, "among": true, "amount": true,
	"amused": true, "analyst": true, "anchor": true, "ancient": true, "anger": true,
	"angle": true, "angry": true, "animal": true, "ankle": true, "announce": true,
	"annual": true, "another": true, "answer": true, "antenna": true, "antique": true,
	"anxiety": true, "any": true, "apart": true, "apology": true, "appear": true,
	"apple": true, "approve": true, "april": true, "arch": true, "arctic": true,
	"area": true, "arena": true, "argue": true, "arm": true, "armed": true,
	"armor": true, "army": true, "around": true, "arrange": true, "arrest": true,
}

// Scan performs a comprehensive crypto wallet scan
func Scan(opts ScanOptions) (*ScanResult, error) {
	result := &ScanResult{
		WalletsFound:     []Wallet{},
		WalletFiles:      []WalletFile{},
		SeedPhrases:      []SeedPhrase{},
		AddressesInFiles: []AddressFind{},
	}

	homeDir, _ := os.UserHomeDir()

	// Scan known wallet locations
	if opts.ScanCommon || opts.ScanHome {
		for _, loc := range walletLocations {
			var fullPath string
			if loc.AbsPath != "" {
				fullPath = loc.AbsPath
			} else if loc.RelPath != "" {
				fullPath = filepath.Join(homeDir, loc.RelPath)
			}

			if fullPath == "" {
				continue
			}

			// Check platform compatibility
			if runtime.GOOS != "darwin" && strings.Contains(loc.RelPath, "Library/") {
				continue
			}
			if runtime.GOOS != "linux" && strings.HasPrefix(loc.RelPath, ".") && !strings.HasPrefix(loc.RelPath, ".config") {
				// Skip Linux-specific hidden dirs on non-Linux
				if !strings.Contains(loc.RelPath, "/") {
					continue
				}
			}

			if info, err := os.Stat(fullPath); err == nil {
				wallet := Wallet{
					Type:        loc.Type,
					Application: loc.Name,
					Path:        fullPath,
					Size:        info.Size(),
					Modified:    info.ModTime().Format("2006-01-02 15:04:05"),
					Risk:        loc.Risk,
				}

				// Check if wallet is encrypted (basic heuristic)
				if info.IsDir() {
					wallet.Encrypted = checkDirEncrypted(fullPath)
				} else {
					wallet.Encrypted = checkFileEncrypted(fullPath)
				}

				result.WalletsFound = append(result.WalletsFound, wallet)
			}
		}
	}

	// Scan additional paths for wallet files and seed phrases
	scanPaths := opts.Paths
	if opts.ScanHome && homeDir != "" {
		scanPaths = append(scanPaths,
			filepath.Join(homeDir, "Documents"),
			filepath.Join(homeDir, "Desktop"),
			filepath.Join(homeDir, "Downloads"),
		)
	}

	for _, path := range scanPaths {
		if _, err := os.Stat(path); err != nil {
			continue
		}

		filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return nil
			}

			// Skip large files
			if info.Size() > 10*1024*1024 { // 10MB
				return nil
			}

			// Check for wallet-related files
			fileName := strings.ToLower(info.Name())
			walletIndicators := []string{
				"wallet", "seed", "mnemonic", "recovery", "backup",
				"keystore", "private", "secret", ".json", ".dat",
			}

			for _, indicator := range walletIndicators {
				if strings.Contains(fileName, indicator) {
					result.WalletFiles = append(result.WalletFiles, WalletFile{
						Path:        filePath,
						Type:        "potential_wallet",
						Description: "File name suggests wallet data",
						Risk:        "high",
					})
					break
				}
			}

			// Scan text files for seed phrases and addresses
			if isTextFile(filePath) && info.Size() < 1024*1024 {
				seeds, addresses := scanFileForCrypto(filePath)
				result.SeedPhrases = append(result.SeedPhrases, seeds...)
				result.AddressesInFiles = append(result.AddressesInFiles, addresses...)
			}

			return nil
		})
	}

	// Calculate summary
	result.Summary = calculateWalletSummary(result)

	return result, nil
}

// scanFileForCrypto scans a file for seed phrases and crypto addresses
func scanFileForCrypto(filePath string) ([]SeedPhrase, []AddressFind) {
	var seeds []SeedPhrase
	var addresses []AddressFind

	file, err := os.Open(filePath)
	if err != nil {
		return seeds, addresses
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		lowerLine := strings.ToLower(line)

		// Check for potential seed phrases (12 or 24 words)
		words := strings.Fields(lowerLine)
		if len(words) == 12 || len(words) == 24 {
			bip39Count := 0
			for _, word := range words {
				if bip39SampleWords[word] {
					bip39Count++
				}
			}

			// If more than half the words are BIP39, likely a seed phrase
			if float64(bip39Count)/float64(len(words)) > 0.5 {
				seeds = append(seeds, SeedPhrase{
					File:      filePath,
					Line:      lineNum,
					WordCount: len(words),
					Redacted:  words[0] + " ... (" + strconv.Itoa(len(words)) + " words)",
					Risk:      "critical",
				})
			}
		}

		// Check for crypto addresses
		for _, ap := range addressPatterns {
			if matches := ap.Pattern.FindAllString(line, -1); matches != nil {
				for _, match := range matches {
					// Skip common false positives
					if isLikelyFalsePositive(match, ap.Type) {
						continue
					}

					addresses = append(addresses, AddressFind{
						File:    filePath,
						Line:    lineNum,
						Type:    ap.Type,
						Address: redactAddress(match),
					})
				}
			}
		}
	}

	return seeds, addresses
}

// checkFileEncrypted does basic encryption detection
func checkFileEncrypted(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	// Read first bytes to check for encryption headers
	header := make([]byte, 16)
	n, err := file.Read(header)
	if err != nil || n < 8 {
		return false
	}

	// Check for common encrypted file signatures
	// Bitcoin Core uses Berkeley DB with encryption
	// Many wallets use AES encryption

	// High entropy in header suggests encryption
	entropy := calculateEntropy(header[:n])
	return entropy > 7.0 // High entropy suggests encryption
}

// checkDirEncrypted checks if wallet directory contains encrypted files
func checkDirEncrypted(path string) bool {
	entries, err := os.ReadDir(path)
	if err != nil {
		return false
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		fullPath := filepath.Join(path, entry.Name())
		if checkFileEncrypted(fullPath) {
			return true
		}
	}
	return false
}

// calculateEntropy calculates Shannon entropy of data
func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	var entropy float64
	dataLen := float64(len(data))

	for _, count := range freq {
		if count > 0 {
			p := float64(count) / dataLen
			entropy -= p * (logBase2(p))
		}
	}

	return entropy
}

func logBase2(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// log2(x) = ln(x) / ln(2)
	return ln(x) / 0.693147180559945
}

func ln(x float64) float64 {
	// Simple natural log approximation
	if x <= 0 {
		return 0
	}
	// Use the series expansion for better accuracy
	result := 0.0
	term := (x - 1) / (x + 1)
	power := term
	for i := 1; i < 100; i += 2 {
		result += power / float64(i)
		power *= term * term
	}
	return 2 * result
}

// isTextFile checks if a file is likely text
func isTextFile(path string) bool {
	textExtensions := []string{
		".txt", ".md", ".json", ".yaml", ".yml", ".xml",
		".csv", ".log", ".conf", ".cfg", ".ini",
		".env", ".sh", ".py", ".js", ".html", ".css",
	}

	ext := strings.ToLower(filepath.Ext(path))
	for _, textExt := range textExtensions {
		if ext == textExt {
			return true
		}
	}

	// Check by reading first bytes
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	buf := make([]byte, 512)
	n, err := file.Read(buf)
	if err != nil || n == 0 {
		return false
	}

	// Check for non-text bytes
	for _, b := range buf[:n] {
		if b == 0 {
			return false // Null byte indicates binary
		}
		if b < 32 && b != 9 && b != 10 && b != 13 {
			return false // Control characters (except tab, newline, carriage return)
		}
	}

	return true
}

// isLikelyFalsePositive checks for common false positives
func isLikelyFalsePositive(match string, cryptoType string) bool {
	// Ethereum: Skip common test/example addresses
	if cryptoType == "ethereum" {
		testAddresses := []string{
			"0x0000000000000000000000000000000000000000",
			"0xffffffffffffffffffffffffffffffffffffffff",
			"0x1234567890123456789012345678901234567890",
		}
		for _, test := range testAddresses {
			if strings.EqualFold(match, test) {
				return true
			}
		}
	}

	// Solana: Many base58 strings aren't actually addresses
	if cryptoType == "solana" {
		// Solana addresses are typically 32-44 characters
		if len(match) < 32 || len(match) > 44 {
			return true
		}
	}

	return false
}

// redactAddress partially redacts a crypto address
func redactAddress(address string) string {
	if len(address) <= 12 {
		return address
	}
	return address[:6] + "..." + address[len(address)-4:]
}

// calculateWalletSummary generates summary statistics
func calculateWalletSummary(result *ScanResult) WalletSummary {
	summary := WalletSummary{
		TotalWallets:     len(result.WalletsFound),
		SeedPhrasesFound: len(result.SeedPhrases),
	}

	for _, wallet := range result.WalletsFound {
		switch wallet.Type {
		case "bitcoin":
			summary.BitcoinWallets++
		case "ethereum":
			summary.EthereumWallets++
		default:
			summary.OtherWallets++
		}

		if wallet.Risk == "critical" {
			summary.CriticalFindings++
		}
	}

	// Seed phrases are always critical
	summary.CriticalFindings += len(result.SeedPhrases)

	return summary
}

// ScanForWalletBackups specifically looks for wallet backup files
func ScanForWalletBackups(path string) ([]WalletFile, error) {
	var backups []WalletFile

	backupPatterns := []string{
		"*.wallet", "*.dat", "wallet-*.json", "*backup*",
		"*seed*", "*mnemonic*", "*recovery*", "*private*key*",
	}

	filepath.Walk(path, func(filePath string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		fileName := strings.ToLower(info.Name())
		for _, pattern := range backupPatterns {
			matched, _ := filepath.Match(pattern, fileName)
			if matched {
				backups = append(backups, WalletFile{
					Path:        filePath,
					Type:        "backup",
					Description: "Potential wallet backup file",
					Risk:        "high",
				})
				break
			}
		}

		return nil
	})

	return backups, nil
}

// ExportResult exports wallet scan results as JSON
func ExportResult(result *ScanResult, outputPath string) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(outputPath, data, 0600)
}
