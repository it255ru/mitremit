// Тесты дедупликации техник и детерминированного порядка вывода (sort by ExternalID).
package tests

import (
	"encoding/json"
	"strings"
	"testing"
)

type techniqueInfo struct {
	ExternalID string `json:"external_id"`
	Name       string `json:"name"`
}

func TestTechniques_NoDuplicatesAndSorted(t *testing.T) {
	bin := getBinary(t)
	stdout, stderr := runMitremit(t, bin, nil, "-json", "-mitigation", "M1037")
	if stderr != "" && strings.Contains(stderr, "error") {
		t.Logf("stderr (may be non-fatal): %s", stderr)
	}
	var results []techniqueInfo
	if err := json.NewDecoder(strings.NewReader(stdout)).Decode(&results); err != nil {
		t.Fatalf("decode JSON output: %v; stdout:\n%s", err, stdout)
	}
	if len(results) == 0 {
		t.Fatalf("expected at least one technique for M1037; got 0")
	}

	// Нет дубликатов по ExternalID
	seen := make(map[string]bool)
	for _, r := range results {
		if seen[r.ExternalID] {
			t.Errorf("duplicate technique ID in output: %s", r.ExternalID)
		}
		seen[r.ExternalID] = true
	}

	// Порядок по возрастанию ExternalID
	for i := 1; i < len(results); i++ {
		if results[i].ExternalID < results[i-1].ExternalID {
			t.Errorf("output not sorted by ExternalID: %s before %s",
				results[i-1].ExternalID, results[i].ExternalID)
		}
	}
}
