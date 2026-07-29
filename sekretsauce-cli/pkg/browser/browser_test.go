package browser

import "testing"

func TestCollectSafariBookmarks(t *testing.T) {
	root := map[string]interface{}{
		"Title": "Bookmarks Bar",
		"Children": []interface{}{
			map[string]interface{}{
				"WebBookmarkType": "WebBookmarkTypeLeaf",
				"URLString":       "https://example.com",
				"URIDictionary": map[string]interface{}{
					"title": "Example",
				},
			},
		},
	}

	var bookmarks []Bookmark
	collectSafariBookmarks(root, "", &bookmarks)
	if len(bookmarks) != 1 {
		t.Fatalf("got %d bookmarks, want 1", len(bookmarks))
	}
	if bookmarks[0].URL != "https://example.com" || bookmarks[0].Folder != "Bookmarks Bar" {
		t.Fatalf("unexpected bookmark: %#v", bookmarks[0])
	}
}
