package keychain

import (
	"errors"
	"testing"
)

func TestFailedDumpIsNotCleanScan(t *testing.T) {
	denied := errors.New("access denied")
	result, err := scanWithDump(func() ([]byte, error) { return nil, denied })
	if !errors.Is(err, denied) || result != nil {
		t.Fatalf("result=%v error=%v", result, err)
	}
}

func TestSuccessfulEmptyDump(t *testing.T) {
	calls := 0
	result, err := scanWithDump(func() ([]byte, error) { calls++; return []byte{}, nil })
	if err != nil || result.TotalItems != 0 || calls != 1 || result.Items == nil {
		t.Fatalf("result=%v error=%v calls=%d", result, err, calls)
	}
}
