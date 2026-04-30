package analyser

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizePCAPInputMapsDBToSiblingPCAP(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "Tuesday.db")
	pcapPath := filepath.Join(dir, "Tuesday.pcap")
	if err := os.WriteFile(dbPath, []byte("SQLite format 3\x00"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pcapPath, []byte{0xd4, 0xc3, 0xb2, 0xa1}, 0644); err != nil {
		t.Fatal(err)
	}

	got, err := normalizePCAPInput("Pcap1", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if got != pcapPath {
		t.Fatalf("normalizePCAPInput() = %q, want %q", got, pcapPath)
	}
}

func TestRequirePCAPRejectsSQLite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Tuesday.db")
	if err := os.WriteFile(path, []byte("SQLite format 3\x00"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := requirePCAP("Pcap1", path); err == nil {
		t.Fatal("requirePCAP accepted sqlite db")
	}
}
