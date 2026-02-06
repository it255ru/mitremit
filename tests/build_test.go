package tests

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestBuild проверяет, что основной пакет (mitremit) успешно собирается.
func TestBuild(t *testing.T) {
	root := repoRoot(t)
	out := filepath.Join(t.TempDir(), "mitremit")
	if goExe := os.Getenv("GOEXE"); goExe != "" {
		out += goExe
	} else if os.PathListSeparator == ';' {
		out += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", out, root)
	cmd.Dir = root
	if err := cmd.Run(); err != nil {
		t.Fatalf("build failed: %v", err)
	}
}
