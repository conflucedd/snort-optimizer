package main

import "testing"

func TestSelectStrategiesDefaultsToAll(t *testing.T) {
	selected, err := selectStrategies(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(selected), len(builtinStrategies()); got != want {
		t.Fatalf("len(selected) = %d, want %d", got, want)
	}
}

func TestSelectStrategiesCanEnableAndDisable(t *testing.T) {
	selected, err := selectStrategies(
		[]string{"safe_source_file_browser", "iter_high_cost_rules"},
		[]string{"iter_high_cost_rules"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(selected), 1; got != want {
		t.Fatalf("len(selected) = %d, want %d", got, want)
	}
	if selected[0].Name != "safe_source_file_browser" {
		t.Fatalf("selected[0].Name = %q, want safe_source_file_browser", selected[0].Name)
	}
}

func TestSelectStrategiesRejectsUnknown(t *testing.T) {
	if _, err := selectStrategies([]string{"missing"}, nil); err == nil {
		t.Fatal("selectStrategies accepted an unknown strategy")
	}
}
