// mitre-mitigates.go
//
// (EN) Tool that, given a MITRE ATT&CK mitigation (by external ID or by name),
// lists every technique / sub‑technique it mitigates.  Output can be a
// table (default), JSON, CSV or Nebula Graph nGQL INSERT statements.
// It automatically downloads the latest ATT&CK enterprise STIX bundle
// and caches the bundle locally.
// 
// (RU) Код на Go выполняет следующие действия:
// Загружает набор данных MITRE ATT&CK в формате STIX (JSON) из репозитория MITRE (или из кэша, если уже скачано).
// Парсит JSON, извлекая объекты: курсы действий (mitigations), методы атаки (techniques) и отношения (relationships).
// Позволяет пользователю указать средство смягчения (mitigation) по его ID (например, M1037) или по имени.
// Находит все методы атаки (techniques), которые смягчаются данным средством, используя отношения (relationships) с типом "mitigates".
// Выводит результат в одном из форматов: таблица (по умолчанию), JSON, CSV или в виде команд nGQL для Nebula Graph.
//
// Build & run:
//
//   go mod init mitremit
//   go build -o mitremit mitre-mitigates.go
//   ./mitremit -mitigation M1037               # table (default)
//   ./mitremit -mitigation M1037 -json > out.json
//   ./mitremit -mitigation-name \"Disable or Remove Feature\" -ngql > out.ngql
//
// 
// --------------------------------------------------------------

package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
)

/*
-------------------------------------------------------------

	Global flag(s)
	-------------------------------------------------------------
*/
var (
	// `-debug` can be placed anywhere on the command line.
	// It defaults to false and is parsed in `main` before any work.
	flagDbg = flag.Bool("debug", false, "extra diagnostic output")
)

/*
-------------------------------------------------------------

	Minimal STIX structures we need
	-------------------------------------------------------------
*/
type Bundle struct {
	Type        string            `json:"type"`
	SpecVersion string            `json:"spec_version"`
	Objects     []json.RawMessage `json:"objects"`
}

// envelope – only type and id are required for the first pass
type baseObject struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Technique / sub‑technique
type attackPattern struct {
	Type         string              `json:"type"`
	ID           string              `json:"id"`
	Name         string              `json:"name"`
	ExternalRefs []externalReference `json:"external_references,omitempty"`
}

// Mitigation
type courseOfAction struct {
	Type         string              `json:"type"`
	ID           string              `json:"id"`
	Name         string              `json:"name"`
	ExternalRefs []externalReference `json:"external_references,omitempty"`
}

// Relationship – we only care about relationship_type == "mitigates"
type relationship struct {
	Type             string `json:"type"`
	ID               string `json:"id"`
	RelationshipType string `json:"relationship_type"`
	SourceRef        string `json:"source_ref"` // mitigation
	TargetRef        string `json:"target_ref"` // technique
}

// External reference (the place where ATT&CK stores the human‑readable ID)
type externalReference struct {
	SourceName string `json:"source_name"` // "mitre-attack"
	ExternalID string `json:"external_id"` // "T1059.001" or "M1037"
	URL        string `json:"url,omitempty"`
}

/*
-------------------------------------------------------------

	Helper – pull the ATT&CK external ID from a slice of refs
	-------------------------------------------------------------
*/
func externalID(refs []externalReference) (string, bool) {
	for _, r := range refs {
		if strings.EqualFold(r.SourceName, "mitre-attack") && r.ExternalID != "" {
			return r.ExternalID, true
		}
	}
	return "", false
}

/*
-------------------------------------------------------------

	Download & cache the ATT&CK bundle
	-------------------------------------------------------------
*/
const (
	bundleURL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
	cacheDir  = ".mitre-cache"
)

func fetchBundle() ([]byte, error) {
	// -----------------------------------------------------------------
	// DEBUG: tell us we entered the function
	// -----------------------------------------------------------------
	if *flagDbg {
		fmt.Fprintln(os.Stdout, ">>> fetchBundle() – entry point")
	}
	// -----------------------------------------------------------------
	// 1️⃣ Ensure a writable cache directory exists
	// -----------------------------------------------------------------
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return nil, err
	}
	bundlePath := filepath.Join(cacheDir, "enterprise-attack.json")

	// -----------------------------------------------------------------
	// 2️⃣ Use cached bundle if it exists
	// -----------------------------------------------------------------
	if cached, err := os.ReadFile(bundlePath); err == nil {
		if *flagDbg {
			fmt.Fprintln(os.Stdout, ">>> cached bundle found – returning cached data")
		}
		return cached, nil // fast path – return cache
	}

	// -----------------------------------------------------------------
	// 3️⃣ Download bundle
	// -----------------------------------------------------------------
	if *flagDbg {
		fmt.Fprintln(os.Stdout, ">>> downloading ATT&CK bundle")
	}
	data, err := downloadBundle()
	if err != nil {
		return nil, err
	}
	if *flagDbg {
		fmt.Fprintf(os.Stdout, ">>> downloaded bundle (%d bytes) – caching\n", len(data))
	}
	_ = os.WriteFile(bundlePath, data, 0o644)
	return data, nil
}

/* ---------- helper used by fetchBundle ---------- */
func downloadBundle() ([]byte, error) {
	resp, err := http.Get(bundleURL)
	if err != nil {
		return nil, fmt.Errorf("download bundle: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bundle HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

/*
-------------------------------------------------------------

	Core extraction logic
	-------------------------------------------------------------
*/
type techniqueInfo struct {
	ExternalID string `json:"external_id"`
	Name       string `json:"name"`
}

func main() {
	/* ---------------------------------------------------------
	   Define command‑line flags
	   --------------------------------------------------------- */
	mitID := flag.String("mitigation", "", "Mitigation external ID (e.g. M1037).")
	mitName := flag.String("mitigation-name", "", "Full mitigation name (case‑insensitive).")
	flagJSON := flag.Bool("json", false, "Emit JSON array.")
	flagCSV := flag.Bool("csv", false, "Emit CSV.")
	flagNGQL := flag.Bool("ngql", false, "Emit Nebula Graph INSERT statements.")
	flagHelp := flag.Bool("h", false, "Show help.")
	// flagDbg is already declared globally

	/* ---------------------------------------------------------
	   IMPORTANT: parse flags *before* any work that uses them
	   --------------------------------------------------------- */
	flag.Parse()

	if *flagHelp || (*mitID == "" && *mitName == "") {
		fmt.Fprintf(os.Stderr,
			`Usage: %s -mitigation Mxxxx [options]
Options:
   -mitigation          ATT&CK mitigation external ID (Mxxxx)
   -mitigation-name    Full mitigation name (case‑insensitive)
   -json                Output JSON
   -csv                 Output CSV
   -ngql                Output Nebula Graph INSERT statements
   -debug               Extra diagnostic output
   -h                   Show this help
`, os.Args[0])
		os.Exit(1)
	}

	/* ---------------------------------------------------------
	   Load the ATT&CK bundle
	   --------------------------------------------------------- */
	raw, err := fetchBundle()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error fetching ATT&CK bundle: %v\n", err)
		os.Exit(1)
	}
	var bundle Bundle
	if err = json.Unmarshal(raw, &bundle); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing bundle JSON: %v\n", err)
		os.Exit(1)
	}

	/* ---------------------------------------------------------
	   Build lookup maps (mitigations, techniques, relationships)
	   --------------------------------------------------------- */
	mitMap := make(map[string]courseOfAction) // key = STIX ID
	techMap := make(map[string]attackPattern) // key = STIX ID
	var rels []relationship

	for _, rawObj := range bundle.Objects {
		var bo baseObject
		if err = json.Unmarshal(rawObj, &bo); err != nil {
			continue // ignore malformed entries
		}
		switch bo.Type {
		case "course-of-action":
			var co courseOfAction
			if err = json.Unmarshal(rawObj, &co); err == nil {
				mitMap[co.ID] = co
			}
		case "attack-pattern":
			var ap attackPattern
			if err = json.Unmarshal(rawObj, &ap); err == nil {
				techMap[ap.ID] = ap
			}
		case "relationship":
			var r relationship
			if err = json.Unmarshal(rawObj, &r); err == nil {
				rels = append(rels, r)
			}
		}
	}

	/* ---------------------------------------------------------
	   Find the mitigation requested by the user
	   --------------------------------------------------------- */
	var chosenMitSTIXID string // STIX ID we will match on source_ref
	if *mitID != "" {
		// lookup by external ID (Mxxxx)
		for id, co := range mitMap {
			if ext, ok := externalID(co.ExternalRefs); ok && strings.EqualFold(ext, *mitID) {
				chosenMitSTIXID = id
				break
			}
		}
		if chosenMitSTIXID == "" {
			fmt.Fprintf(os.Stderr, "mitigation %s not found in ATT&CK data\n", *mitID)
			os.Exit(1)
		}
	} else {
		// lookup by name (case‑insensitive)
		target := strings.TrimSpace(*mitName)
		for id, co := range mitMap {
			if strings.EqualFold(co.Name, target) {
				chosenMitSTIXID = id
				break
			}
		}
		if chosenMitSTIXID == "" {
			fmt.Fprintf(os.Stderr, "mitigation name %q not found (check spelling)\n", target)
			os.Exit(1)
		}
	}

	/* ---------------------------------------------------------
	   Collect all techniques that this mitigation mitigates
	   --------------------------------------------------------- */
	var results []techniqueInfo
	for _, r := range rels {
		if r.RelationshipType != "mitigates" {
			continue
		}
		if r.SourceRef != chosenMitSTIXID {
			continue
		}
		if tp, ok := techMap[r.TargetRef]; ok {
			ext, _ := externalID(tp.ExternalRefs)
			if ext == "" {
				ext = strings.TrimPrefix(tp.ID, "attack-pattern--")
			}
			results = append(results, techniqueInfo{
				ExternalID: ext,
				Name:       tp.Name,
			})
		}
	}
	// deterministic ordering – nice for CSV/JSON diffing
	sort.Slice(results, func(i, j int) bool {
		return results[i].ExternalID < results[j].ExternalID
	})

	/* ---------------------------------------------------------
	   Emit the requested output format
	   --------------------------------------------------------- */
	if *flagNGQL {
		emitNGQL(chosenMitSTIXID, results, mitMap[chosenMitSTIXID])
		return
	}
	if *flagJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
		return
	}
	if *flagCSV {
		w := csv.NewWriter(os.Stdout)
		_ = w.Write([]string{"Mitigation ID", "Mitigation Name", "Technique ID", "Technique Name"})
		mitExt, _ := externalID(mitMap[chosenMitSTIXID].ExternalRefs)
		for _, t := range results {
			_ = w.Write([]string{mitExt, mitMap[chosenMitSTIXID].Name, t.ExternalID, t.Name})
		}
		w.Flush()
		return
	}
	// default: pretty table
	printTable(chosenMitSTIXID, mitMap[chosenMitSTIXID], results)
}

/*
-------------------------------------------------------------

	Pretty‑print table (default output)
	-------------------------------------------------------------
*/
func printTable(mitSTIX string, mit courseOfAction, data []techniqueInfo) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	mitExt, _ := externalID(mit.ExternalRefs)
	fmt.Fprintf(w, "MITIGATION\t%s (%s)\n", mit.Name, mitExt)
	fmt.Fprintln(w, "---------------------------------------------------------------")
	fmt.Fprintln(w, "TECHNIQUE ID\tTECHNIQUE NAME")
	for _, t := range data {
		fmt.Fprintf(w, "%s\t%s\n", t.ExternalID, t.Name)
	}
	_ = w.Flush()
}

/*
-------------------------------------------------------------

	Nebula Graph nGQL generation
	-------------------------------------------------------------
*/
func quoteID(s string) string {
	return "`" + strings.ReplaceAll(s, "`", "``") + "`"
}
func quoteLiteral(s string) string { return strconv.Quote(s) }

func emitNGQL(mitSTIX string, techs []techniqueInfo, mit courseOfAction) {
	var b strings.Builder
	mitExt, _ := externalID(mit.ExternalRefs)

	// mitigation vertex
	fmt.Fprintf(&b, "INSERT VERTEX mitigation(id, name) VALUES %s:(%s, %s);\n",
		quoteID(mitExt), quoteLiteral(mitExt), quoteLiteral(mit.Name))

	// technique vertices
	for _, t := range techs {
		fmt.Fprintf(&b, "INSERT VERTEX technique(id, name) VALUES %s:(%s, %s);\n",
			quoteID(t.ExternalID), quoteLiteral(t.ExternalID), quoteLiteral(t.Name))
	}

	// edges: mitigation -> technique
	for _, t := range techs {
		fmt.Fprintf(&b, "INSERT EDGE mitigates() VALUES %s -> %s;\n",
			quoteID(mitExt), quoteID(t.ExternalID))
	}
	fmt.Print(b.String())
}
