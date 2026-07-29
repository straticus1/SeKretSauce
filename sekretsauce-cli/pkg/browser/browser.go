package browser

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// ExportOptions configures what to export
type ExportOptions struct {
	IncludePasswords bool
	IncludeHistory   bool
	IncludeBookmarks bool
	IncludeSettings  bool
}

// ExportResult contains exported browser data
type ExportResult struct {
	Browser  string    `json:"browser"`
	Profiles []Profile `json:"profiles"`
}

// Profile represents a browser profile
type Profile struct {
	Name      string                 `json:"name"`
	Path      string                 `json:"path"`
	Bookmarks []Bookmark             `json:"bookmarks,omitempty"`
	History   []HistoryEntry         `json:"history,omitempty"`
	Passwords []Password             `json:"passwords,omitempty"`
	Settings  map[string]interface{} `json:"settings,omitempty"`
}

// Bookmark represents a browser bookmark
type Bookmark struct {
	Title     string    `json:"title"`
	URL       string    `json:"url"`
	Folder    string    `json:"folder"`
	DateAdded time.Time `json:"date_added"`
}

// HistoryEntry represents a browsing history entry
type HistoryEntry struct {
	Title      string    `json:"title"`
	URL        string    `json:"url"`
	VisitCount int       `json:"visit_count"`
	LastVisit  time.Time `json:"last_visit"`
}

// Password represents a saved password (credentials only extracted with explicit auth)
type Password struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	// Note: actual passwords require explicit authorization and keychain access
	HasPassword bool `json:"has_password"`
}

// Export extracts data from a browser
func Export(browserName string, opts ExportOptions) (*ExportResult, error) {
	switch browserName {
	case "firefox", "ff":
		return exportFirefox(opts)
	case "chrome", "gc":
		return exportChrome(opts)
	case "safari":
		return exportSafari(opts)
	default:
		return nil, fmt.Errorf("unsupported browser: %s", browserName)
	}
}

func exportFirefox(opts ExportOptions) (*ExportResult, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("cannot find home directory: %w", err)
	}

	profilesPath := filepath.Join(homeDir, "Library", "Application Support", "Firefox", "Profiles")

	if _, err := os.Stat(profilesPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("Firefox profiles not found at %s", profilesPath)
	}

	entries, err := os.ReadDir(profilesPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read Firefox profiles: %w", err)
	}

	result := &ExportResult{
		Browser:  "firefox",
		Profiles: []Profile{},
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		profilePath := filepath.Join(profilesPath, entry.Name())
		profile := Profile{
			Name: entry.Name(),
			Path: profilePath,
		}

		// Export history from places.sqlite
		if opts.IncludeHistory {
			history, err := exportFirefoxHistory(profilePath)
			if err == nil {
				profile.History = history
			}
		}

		// Export bookmarks from places.sqlite
		if opts.IncludeBookmarks {
			bookmarks, err := exportFirefoxBookmarks(profilePath)
			if err == nil {
				profile.Bookmarks = bookmarks
			}
		}

		// Export settings from prefs.js
		if opts.IncludeSettings {
			settings, err := exportFirefoxSettings(profilePath)
			if err == nil {
				profile.Settings = settings
			}
		}

		result.Profiles = append(result.Profiles, profile)
	}

	if len(result.Profiles) == 0 {
		return nil, fmt.Errorf("no Firefox profiles found")
	}

	return result, nil
}

func exportFirefoxHistory(profilePath string) ([]HistoryEntry, error) {
	dbPath := filepath.Join(profilePath, "places.sqlite")

	// Copy database to avoid lock issues
	tmpDB, err := copyDBForReading(dbPath)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpDB)

	db, err := sql.Open("sqlite3", tmpDB+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT p.title, p.url, p.visit_count, p.last_visit_date
		FROM moz_places p
		WHERE p.url NOT LIKE 'place:%'
		ORDER BY p.last_visit_date DESC
		LIMIT 1000
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []HistoryEntry
	for rows.Next() {
		var entry HistoryEntry
		var title sql.NullString
		var lastVisit sql.NullInt64

		if err := rows.Scan(&title, &entry.URL, &entry.VisitCount, &lastVisit); err != nil {
			continue
		}

		if title.Valid {
			entry.Title = title.String
		}
		if lastVisit.Valid {
			// Firefox stores time in microseconds since epoch
			entry.LastVisit = time.UnixMicro(lastVisit.Int64)
		}

		history = append(history, entry)
	}

	return history, nil
}

func exportFirefoxBookmarks(profilePath string) ([]Bookmark, error) {
	dbPath := filepath.Join(profilePath, "places.sqlite")

	tmpDB, err := copyDBForReading(dbPath)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpDB)

	db, err := sql.Open("sqlite3", tmpDB+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT b.title, p.url, parent.title as folder, b.dateAdded
		FROM moz_bookmarks b
		JOIN moz_places p ON b.fk = p.id
		LEFT JOIN moz_bookmarks parent ON b.parent = parent.id
		WHERE b.type = 1
		ORDER BY b.dateAdded DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bookmarks []Bookmark
	for rows.Next() {
		var bm Bookmark
		var title, folder sql.NullString
		var dateAdded sql.NullInt64

		if err := rows.Scan(&title, &bm.URL, &folder, &dateAdded); err != nil {
			continue
		}

		if title.Valid {
			bm.Title = title.String
		}
		if folder.Valid {
			bm.Folder = folder.String
		}
		if dateAdded.Valid {
			bm.DateAdded = time.UnixMicro(dateAdded.Int64)
		}

		bookmarks = append(bookmarks, bm)
	}

	return bookmarks, nil
}

func exportFirefoxSettings(profilePath string) (map[string]interface{}, error) {
	prefsPath := filepath.Join(profilePath, "prefs.js")

	data, err := os.ReadFile(prefsPath)
	if err != nil {
		return nil, err
	}

	// Parse basic user preferences (simplified)
	settings := map[string]interface{}{
		"raw_prefs_size": len(data),
		"prefs_path":     prefsPath,
	}

	return settings, nil
}

func exportChrome(opts ExportOptions) (*ExportResult, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("cannot find home directory: %w", err)
	}

	chromePath := filepath.Join(homeDir, "Library", "Application Support", "Google", "Chrome")

	if _, err := os.Stat(chromePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("Chrome data not found at %s", chromePath)
	}

	result := &ExportResult{
		Browser:  "chrome",
		Profiles: []Profile{},
	}

	// Check for Default profile and numbered profiles
	profileDirs := []string{"Default"}
	entries, _ := os.ReadDir(chromePath)
	for _, entry := range entries {
		if entry.IsDir() && len(entry.Name()) > 7 && entry.Name()[:7] == "Profile" {
			profileDirs = append(profileDirs, entry.Name())
		}
	}

	for _, profileName := range profileDirs {
		profilePath := filepath.Join(chromePath, profileName)
		if _, err := os.Stat(profilePath); os.IsNotExist(err) {
			continue
		}

		profile := Profile{
			Name: profileName,
			Path: profilePath,
		}

		if opts.IncludeHistory {
			history, err := exportChromeHistory(profilePath)
			if err == nil {
				profile.History = history
			}
		}

		if opts.IncludeBookmarks {
			bookmarks, err := exportChromeBookmarks(profilePath)
			if err == nil {
				profile.Bookmarks = bookmarks
			}
		}

		if opts.IncludeSettings {
			settings, err := exportChromeSettings(profilePath)
			if err == nil {
				profile.Settings = settings
			}
		}

		result.Profiles = append(result.Profiles, profile)
	}

	if len(result.Profiles) == 0 {
		return nil, fmt.Errorf("no Chrome profiles found")
	}

	return result, nil
}

func exportChromeHistory(profilePath string) ([]HistoryEntry, error) {
	dbPath := filepath.Join(profilePath, "History")

	tmpDB, err := copyDBForReading(dbPath)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpDB)

	db, err := sql.Open("sqlite3", tmpDB+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT title, url, visit_count, last_visit_time
		FROM urls
		ORDER BY last_visit_time DESC
		LIMIT 1000
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []HistoryEntry
	for rows.Next() {
		var entry HistoryEntry
		var title sql.NullString
		var lastVisit int64

		if err := rows.Scan(&title, &entry.URL, &entry.VisitCount, &lastVisit); err != nil {
			continue
		}

		if title.Valid {
			entry.Title = title.String
		}
		// Chrome stores time as microseconds since Jan 1, 1601
		if lastVisit > 0 {
			// Convert WebKit/Chrome timestamp to Unix timestamp
			entry.LastVisit = time.Unix((lastVisit/1000000)-11644473600, 0)
		}

		history = append(history, entry)
	}

	return history, nil
}

func exportChromeBookmarks(profilePath string) ([]Bookmark, error) {
	bookmarksPath := filepath.Join(profilePath, "Bookmarks")

	data, err := os.ReadFile(bookmarksPath)
	if err != nil {
		return nil, err
	}

	var bookmarksData struct {
		Roots map[string]json.RawMessage `json:"roots"`
	}

	if err := json.Unmarshal(data, &bookmarksData); err != nil {
		return nil, err
	}

	var bookmarks []Bookmark
	for _, root := range bookmarksData.Roots {
		extractChromeBookmarks(root, "", &bookmarks)
	}

	return bookmarks, nil
}

func extractChromeBookmarks(data json.RawMessage, folder string, bookmarks *[]Bookmark) {
	var node struct {
		Type      string            `json:"type"`
		Name      string            `json:"name"`
		URL       string            `json:"url"`
		DateAdded string            `json:"date_added"`
		Children  []json.RawMessage `json:"children"`
	}

	if err := json.Unmarshal(data, &node); err != nil {
		return
	}

	if node.Type == "url" {
		bm := Bookmark{
			Title:  node.Name,
			URL:    node.URL,
			Folder: folder,
		}
		*bookmarks = append(*bookmarks, bm)
	} else if node.Type == "folder" {
		newFolder := folder
		if folder == "" {
			newFolder = node.Name
		} else {
			newFolder = folder + "/" + node.Name
		}
		for _, child := range node.Children {
			extractChromeBookmarks(child, newFolder, bookmarks)
		}
	}
}

func exportChromeSettings(profilePath string) (map[string]interface{}, error) {
	prefsPath := filepath.Join(profilePath, "Preferences")

	data, err := os.ReadFile(prefsPath)
	if err != nil {
		return nil, err
	}

	var prefs map[string]interface{}
	if err := json.Unmarshal(data, &prefs); err != nil {
		return nil, err
	}

	// Return a sanitized subset of settings
	settings := map[string]interface{}{
		"prefs_path": prefsPath,
	}

	// Extract some common settings if available
	if browser, ok := prefs["browser"].(map[string]interface{}); ok {
		if enabled, ok := browser["enabled_labs_experiments"]; ok {
			settings["experiments"] = enabled
		}
	}

	return settings, nil
}

func exportSafari(opts ExportOptions) (*ExportResult, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("cannot find home directory: %w", err)
	}

	safariPath := filepath.Join(homeDir, "Library", "Safari")

	if _, err := os.Stat(safariPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("Safari data not found at %s", safariPath)
	}

	profile := Profile{
		Name: "Default",
		Path: safariPath,
	}

	if opts.IncludeHistory {
		history, err := exportSafariHistory(safariPath)
		if err == nil {
			profile.History = history
		}
	}

	if opts.IncludeBookmarks {
		bookmarks, err := exportSafariBookmarks(safariPath)
		if err == nil {
			profile.Bookmarks = bookmarks
		}
	}

	return &ExportResult{
		Browser:  "safari",
		Profiles: []Profile{profile},
	}, nil
}

func exportSafariHistory(safariPath string) ([]HistoryEntry, error) {
	dbPath := filepath.Join(safariPath, "History.db")

	tmpDB, err := copyDBForReading(dbPath)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpDB)

	db, err := sql.Open("sqlite3", tmpDB+"?mode=ro")
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(`
		SELECT hi.url, hv.title, hv.visit_time
		FROM history_items hi
		JOIN history_visits hv ON hi.id = hv.history_item
		ORDER BY hv.visit_time DESC
		LIMIT 1000
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []HistoryEntry
	for rows.Next() {
		var entry HistoryEntry
		var title sql.NullString
		var visitTime float64

		if err := rows.Scan(&entry.URL, &title, &visitTime); err != nil {
			continue
		}

		if title.Valid {
			entry.Title = title.String
		}
		// Safari stores time as seconds since Jan 1, 2001
		if visitTime > 0 {
			entry.LastVisit = time.Unix(int64(visitTime)+978307200, 0)
		}
		entry.VisitCount = 1

		history = append(history, entry)
	}

	return history, nil
}

func exportSafariBookmarks(safariPath string) ([]Bookmark, error) {
	// Safari bookmarks are in a plist file
	bookmarksPath := filepath.Join(safariPath, "Bookmarks.plist")

	if _, err := os.Stat(bookmarksPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("Safari bookmarks not found")
	}

	command := exec.Command("/usr/bin/plutil", "-convert", "json", "-o", "-", bookmarksPath)
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("convert Safari bookmarks: %w", err)
	}
	if len(output) > 16<<20 {
		return nil, fmt.Errorf("Safari bookmarks plist exceeds 16 MiB")
	}

	var root map[string]interface{}
	if err := json.Unmarshal(output, &root); err != nil {
		return nil, fmt.Errorf("parse Safari bookmarks: %w", err)
	}
	var bookmarks []Bookmark
	collectSafariBookmarks(root, "", &bookmarks)
	return bookmarks, nil
}

func collectSafariBookmarks(node map[string]interface{}, folder string, bookmarks *[]Bookmark) {
	nodeType, _ := node["WebBookmarkType"].(string)
	if nodeType == "WebBookmarkTypeLeaf" {
		urlString, _ := node["URLString"].(string)
		if urlString == "" {
			return
		}
		title := ""
		if uriDictionary, ok := node["URIDictionary"].(map[string]interface{}); ok {
			title, _ = uriDictionary["title"].(string)
		}
		*bookmarks = append(*bookmarks, Bookmark{
			Title:  title,
			URL:    urlString,
			Folder: folder,
		})
		return
	}

	nextFolder := folder
	if title, ok := node["Title"].(string); ok && title != "" {
		nextFolder = title
	}
	if children, ok := node["Children"].([]interface{}); ok {
		for _, child := range children {
			if childNode, ok := child.(map[string]interface{}); ok {
				collectSafariBookmarks(childNode, nextFolder, bookmarks)
			}
		}
	}
}

func copyDBForReading(srcPath string) (string, error) {
	// Create a temporary copy to avoid database lock issues
	tmpFile, err := os.CreateTemp("", "sekretsauce-*.db")
	if err != nil {
		return "", err
	}
	tmpFile.Close()

	source, err := os.Open(srcPath)
	if err != nil {
		os.Remove(tmpFile.Name())
		return "", err
	}
	defer source.Close()

	destination, err := os.OpenFile(tmpFile.Name(), os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		os.Remove(tmpFile.Name())
		return "", err
	}
	_, copyError := io.Copy(destination, source)
	closeError := destination.Close()
	if copyError != nil {
		os.Remove(tmpFile.Name())
		return "", copyError
	}
	if closeError != nil {
		os.Remove(tmpFile.Name())
		return "", closeError
	}

	return tmpFile.Name(), nil
}
