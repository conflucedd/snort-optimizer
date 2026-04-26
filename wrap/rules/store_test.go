package rules

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"snort-optimizer/wrap/sqliteutil"
)

func TestEnsureDBGenerateAndDisableRule(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		t.Fatal(err)
	}
	content := strings.Join([]string{
		`alert tcp any any -> any any (msg:"one"; sid:1001; gid:1; rev:1; classtype:attempted-admin;)`,
		`# alert tcp any any -> any any (msg:"commented"; sid:9999; rev:1;)`,
		`alert udp any any -> any any (msg:"two"; sid:1002; rev:2;)`,
	}, "\n")
	if err := os.WriteFile(filepath.Join(rulesDir, "local.rules"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	logger := log.New(os.Stderr, "test: ", 0)
	if err := EnsureDB(dir, logger); err != nil {
		t.Fatal(err)
	}
	rows, err := sqliteutil.QueryJSON(DBPath(dir), "SELECT id, sid FROM rules ORDER BY id;")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 parsed rules, got %d", len(rows))
	}

	if err := GenerateAllRules(dir); err != nil {
		t.Fatal(err)
	}
	allRules, err := os.ReadFile(AllRulesPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(allRules), "sid:1001") || !strings.Contains(string(allRules), "sid:1002") {
		t.Fatalf("generated all.rules is missing enabled rules: %s", allRules)
	}

	id := int64(rows[0]["id"].(float64))
	if err := SetEnabled(dir, id, false); err != nil {
		t.Fatal(err)
	}
	if err := GenerateAllRules(dir); err != nil {
		t.Fatal(err)
	}
	allRules, err = os.ReadFile(AllRulesPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(allRules), "sid:1001") || !strings.Contains(string(allRules), "sid:1002") {
		t.Fatalf("disable by primary key did not affect all.rules: %s", allRules)
	}
}

func TestParseServiceOnlyRule(t *testing.T) {
	rule, err := ParseRule(`alert http ( msg:"service only"; sid:300001; rev:1; )`, "local.rules")
	if err != nil {
		t.Fatal(err)
	}
	if rule.Action != "alert" || rule.Proto != "http" || rule.SID != 300001 {
		t.Fatalf("unexpected parsed rule: %+v", rule)
	}
	if rule.SrcNet != "" || rule.Direction != "" || rule.DstNet != "" {
		t.Fatalf("service-only rule should not invent address fields: %+v", rule)
	}
}
