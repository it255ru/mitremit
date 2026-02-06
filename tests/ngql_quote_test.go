// Тесты экранирования идентификаторов в nGQL (защита от nGQL injection).
// Проверяют, что в выводе -ngql идентификаторы содержат только разрешённые символы: буквы, цифры, '-', '_', '.'.
package tests

import (
	"strings"
	"testing"
	"unicode"
)

// allowedIDRune проверяет, что руна разрешена внутри экранированного идентификатора nGQL.
func allowedIDRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.'
}

// extractBacktickIDs возвращает все подстроки между парными обратными кавычками (с учётом `` как экранирования).
func extractBacktickIDs(s string) []string {
	var ids []string
	i := 0
	for i < len(s) {
		if s[i] != '`' {
			i++
			continue
		}
		i++
		var b strings.Builder
		for i < len(s) {
			if s[i] == '`' {
				if i+1 < len(s) && s[i+1] == '`' {
					b.WriteByte('`')
					i += 2
					continue
				}
				i++
				break
			}
			b.WriteByte(s[i])
			i++
		}
		if b.Len() > 0 {
			ids = append(ids, b.String())
		}
	}
	return ids
}

func TestNGQL_IdentifiersOnlySafeChars(t *testing.T) {
	bin := getBinary(t)
	stdout, _ := runMitremit(t, bin, nil, "-ngql", "-mitigation", "M1037")

	ids := extractBacktickIDs(stdout)
	if len(ids) == 0 {
		t.Fatalf("expected at least one backtick-quoted identifier in nGQL output; got:\n%s", stdout)
	}
	for _, id := range ids {
		for _, r := range id {
			if !allowedIDRune(r) {
				t.Errorf("nGQL identifier %q contains disallowed rune %q (U+%04X); full output:\n%s", id, r, r, stdout)
			}
		}
	}
}

// Проверяем, что в выводе нет опасных подстрок (инъекция через точку с запятой вне строкового литерала).
func TestNGQL_NoUnquotedSemicolonsInIdentifiers(t *testing.T) {
	bin := getBinary(t)
	stdout, _ := runMitremit(t, bin, nil, "-ngql", "-mitigation", "M1037")

	// Идентификаторы в nGQL выводе имеют вид `id`; внутри кавычек не должно быть ; (sanitize заменяет на _)
	ids := extractBacktickIDs(stdout)
	for _, id := range ids {
		if strings.ContainsRune(id, ';') {
			t.Errorf("nGQL identifier must not contain semicolon (injection risk): %q", id)
		}
	}
}
