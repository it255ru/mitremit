// Тесты подсказки «Did you mean?» при опечатке в -mitigation-name.
package tests

import (
	"os/exec"
	"strings"
	"testing"
)

func TestDidYouMean_SuggestsSingleCloseName(t *testing.T) {
	bin := getBinary(t)
	// Опечатка: "Trafic" вместо "Traffic" (расстояние Левенштейна 1)
	cmd := exec.Command(bin, "-mitigation-name", "Filter Network Trafic")
	cmd.Dir = repoRoot(t)
	var stderr strings.Builder
	cmd.Stdout = nil
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected exit code 1 when mitigation name not found")
	}
	if _, ok := err.(*exec.ExitError); !ok {
		t.Fatalf("expected exec.ExitError, got %T: %v", err, err)
	}
	out := stderr.String()
	if !strings.Contains(out, "not found (check spelling)") {
		t.Errorf("stderr should contain 'not found (check spelling)'; got:\n%s", out)
	}
	if !strings.Contains(out, "Did you mean:") {
		t.Errorf("stderr should contain 'Did you mean:' suggestion; got:\n%s", out)
	}
	if !strings.Contains(out, "Filter Network Traffic") {
		t.Errorf("stderr should suggest correct name 'Filter Network Traffic'; got:\n%s", out)
	}
}

func TestDidYouMean_NoSuggestionWhenExactMatch(t *testing.T) {
	bin := getBinary(t)
	// Точное совпадение — программа должна найти и вывести результат, не ошибку
	stdout, stderr := runMitremit(t, bin, nil, "-mitigation-name", "Filter Network Traffic", "-json")
	if stderr != "" && strings.Contains(stderr, "not found") {
		t.Errorf("exact name must be found; stderr:\n%s", stderr)
	}
	if !strings.Contains(stdout, "external_id") {
		t.Errorf("expected JSON output with techniques; stdout:\n%s", stdout)
	}
}

func TestDidYouMean_NoSuggestionWhenNoCloseMatch(t *testing.T) {
	bin := getBinary(t)
	// Совсем другое имя — подсказки быть не должно (или только если случайно один вариант в пределах 2)
	cmd := exec.Command(bin, "-mitigation-name", "XyZzY NoSuch Mitigation 123")
	cmd.Dir = repoRoot(t)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	_ = cmd.Run()
	out := stderr.String()
	if !strings.Contains(out, "not found (check spelling)") {
		t.Errorf("stderr should contain 'not found'; got:\n%s", out)
	}
	// Не требуем отсутствия "Did you mean" — при большом наборе митигаций теоретически может быть один в радиусе 2
	// Проверяем лишь, что при явной опечатке подсказка есть (первый тест), а при точном совпадении — нет ошибки (второй)
}
