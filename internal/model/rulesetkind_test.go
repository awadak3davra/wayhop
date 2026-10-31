package model

import "testing"

func TestRuleSetURLKind(t *testing.T) {
	for in, want := range map[string]string{
		"https://example.com/lists/ru.srs":          "binary",
		"https://example.com/lists/RU.SRS?raw=true": "binary",
		"https://example.com/lists/ru.json#x":       "source",
		"https://example.com/lists/ru.lst":          "text",
		"https://example.com/lists/ru.txt":          "text",
		"https://cdn.example.com/rules/ru-bundle":   "",
		"https://example.com/get?list=ru.srs":       "",
		"https://example.com":                       "",
		"https://example.com/":                      "",
		"https://example.com/v1.2/list":             "",
	} {
		if got := RuleSetURLKind(in); got != want {
			t.Errorf("RuleSetURLKind(%q) = %q, want %q", in, got, want)
		}
	}
}
