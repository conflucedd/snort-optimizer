package analyser

import (
	"os"
	"path/filepath"
	"testing"

	"snort-optimizer/analyser/safe"
	"snort-optimizer/analyser/types"
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

func TestNewDoesNotRegisterDefaultFunctions(t *testing.T) {
	cfg := testConfig(t)
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(a.Functions()); got != 0 {
		t.Fatalf("len(Functions()) = %d, want 0", got)
	}

	a.RegisterAll(safe.SourceFileBrowser())
	if got := len(a.Functions()); got != 1 {
		t.Fatalf("len(Functions()) after RegisterAll = %d, want 1", got)
	}
}

func testConfig(t *testing.T) types.Config {
	t.Helper()
	dir := t.TempDir()
	pcap1 := filepath.Join(dir, "one.pcap")
	pcap2 := filepath.Join(dir, "two.pcap")
	db1 := filepath.Join(dir, "flows.db")
	snortConfig := filepath.Join(dir, "snort.lua")
	rawRules := filepath.Join(dir, "rules")
	for _, path := range []string{pcap1, pcap2} {
		if err := os.WriteFile(path, []byte{0xd4, 0xc3, 0xb2, 0xa1}, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(db1, []byte("SQLite format 3\x00"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snortConfig, []byte("ips = {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(rawRules, 0755); err != nil {
		t.Fatal(err)
	}
	return types.Config{
		Pcap1:       pcap1,
		DB1:         db1,
		Pcap2:       pcap2,
		SnortConfig: snortConfig,
		RawRulePath: rawRules,
	}
}
