// Тесты TTL кэша: свежий кэш используется, устаревший — игнорируется (загрузка заново).
package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	cacheFilename     = "enterprise-attack.json"
	cacheTTL          = 24 * time.Hour
	minimalBundleJSON = `{"type":"bundle","spec_version":"2.0","objects":[]}`
)

func TestCacheTTL_FreshCacheUsed(t *testing.T) {
	bin := getBinary(t)
	cacheDir := t.TempDir()
	bundlePath := filepath.Join(cacheDir, cacheFilename)
	if err := os.WriteFile(bundlePath, []byte(minimalBundleJSON), 0o644); err != nil {
		t.Fatalf("write cache file: %v", err)
	}
	// Модификация только что — кэш считается свежим
	stdout, _ := runMitremit(t, bin, map[string]string{envMITRECacheDir: cacheDir},
		"-debug", "-mitigation", "M1037")

	if !strings.Contains(stdout, "cached bundle found") {
		t.Errorf("expected stdout to contain 'cached bundle found' when cache is fresh; stdout:\n%s", stdout)
	}
	if strings.Contains(stdout, "cache expired or missing") {
		t.Errorf("fresh cache must not be treated as expired; stdout:\n%s", stdout)
	}
}

func TestCacheTTL_ExpiredCacheIgnored(t *testing.T) {
	bin := getBinary(t)
	cacheDir := t.TempDir()
	bundlePath := filepath.Join(cacheDir, cacheFilename)
	if err := os.WriteFile(bundlePath, []byte(minimalBundleJSON), 0o644); err != nil {
		t.Fatalf("write cache file: %v", err)
	}
	// Делаем файл «старым» (старше cacheTTL)
	oldTime := time.Now().Add(-(cacheTTL + time.Hour))
	if err := os.Chtimes(bundlePath, oldTime, oldTime); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	stdout, _ := runMitremit(t, bin, map[string]string{envMITRECacheDir: cacheDir},
		"-debug", "-mitigation", "M1037")

	if !strings.Contains(stdout, "cache expired or missing") {
		t.Errorf("expected stdout to contain 'cache expired or missing' when cache is older than TTL; stdout:\n%s", stdout)
	}
	if strings.Contains(stdout, "cached bundle found") {
		t.Errorf("expired cache must not be used; stdout:\n%s", stdout)
	}
}
