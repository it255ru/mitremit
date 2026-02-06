// Тесты вывода тактик (tactics) из kill_chain_phases во всех форматах.
package tests

import (
	"encoding/json"
	"strings"
	"testing"
)

type techniqueInfoWithTactics struct {
	ExternalID string   `json:"external_id"`
	Name       string   `json:"name"`
	Tactics    []string `json:"tactics,omitempty"`
}

func TestTactics_JSONContainsTactics(t *testing.T) {
	bin := getBinary(t)
	stdout, stderr := runMitremit(t, bin, nil, "-json", "-mitigation", "M1037")
	if stderr != "" && strings.Contains(stderr, "error") {
		t.Logf("stderr: %s", stderr)
	}
	var results []techniqueInfoWithTactics
	if err := json.NewDecoder(strings.NewReader(stdout)).Decode(&results); err != nil {
		t.Fatalf("decode JSON: %v; stdout:\n%s", err, stdout)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one technique for M1037")
	}
	// В ATT&CK у техник есть kill_chain_phases (тактики); хотя бы у одной непустой tactics
	hasTactics := false
	for _, r := range results {
		if len(r.Tactics) > 0 {
			hasTactics = true
			break
		}
	}
	if !hasTactics {
		t.Errorf("expected at least one technique with non-empty tactics; got %d techniques without tactics", len(results))
	}
}

func TestTactics_TableOutputContainsTacticsColumn(t *testing.T) {
	bin := getBinary(t)
	stdout, _ := runMitremit(t, bin, nil, "-mitigation", "M1037")
	if !strings.Contains(stdout, "TACTICS") {
		t.Errorf("table output should contain TACTICS column header; got:\n%s", stdout)
	}
	// Строка заголовка: TECHNIQUE ID, TECHNIQUE NAME, TACTICS
	lines := strings.Split(stdout, "\n")
	foundHeader := false
	for _, line := range lines {
		if strings.Contains(line, "TECHNIQUE ID") && strings.Contains(line, "TACTICS") {
			foundHeader = true
			break
		}
	}
	if !foundHeader {
		t.Errorf("table must have header line with TECHNIQUE ID and TACTICS; got:\n%s", stdout)
	}
}

func TestTactics_CSVContainsTacticsColumn(t *testing.T) {
	bin := getBinary(t)
	stdout, _ := runMitremit(t, bin, nil, "-csv", "-mitigation", "M1037")
	if !strings.Contains(stdout, "Tactics") {
		t.Errorf("CSV output should contain Tactics column; got:\n%s", stdout)
	}
	firstLine := strings.Split(stdout, "\n")[0]
	if !strings.Contains(firstLine, "Tactics") {
		t.Errorf("CSV header must include Tactics; first line: %s", firstLine)
	}
}
