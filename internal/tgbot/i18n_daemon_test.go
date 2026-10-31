package tgbot

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// A Russian or Ukrainian chat reads the Diagnostics findings in its language: the router's fixed
// sentences and the ones with a number in them. What the bot does not know stays as written.
func TestDiagSpeaksTheChatsLanguage(t *testing.T) {
	checks := []Check{
		{ID: "ipv6", Status: "fail", Summary: "IPv6 reaches the internet directly",
			Fix: "Your device can use IPv6 to bypass the VPN and expose your real address. Disable IPv6 on the router, or block IPv6 forwarding."},
		{ID: "endpoint_reach", Status: "warn", Summary: "2 of 5 endpoint(s) unreachable"},
		{ID: "pbr_kernel", Status: "warn", Summary: "hybrid mode but plan not installed — click Apply",
			Fix: "Apply a config with at least one routing list to activate kernel PBR."},
		{ID: "custom", Label: "Something new", Status: "warn", Summary: "a sentence this build does not know"},
	}
	for _, tc := range []struct {
		lang string
		want []string
	}{
		{"en", []string{"IPv6 reaches the internet directly", "2 of 5 endpoint(s) unreachable", "hybrid mode but plan not installed", "a sentence this build does not know"}},
		{"ru", []string{"IPv6 выходит в интернет напрямую", "Отключите IPv6 на роутере", "недоступно подключений: 2 из 5",
			"режим hybrid, но план не установлен — нажмите «Применить»", "активировать PBR ядра", "a sentence this build does not know"}},
		{"uk", []string{"IPv6 виходить в інтернет напряму", "Вимкніть IPv6 на роутері", "недоступно підключень: 2 з 5",
			"режим hybrid, але план не встановлено", "a sentence this build does not know"}},
	} {
		text, _ := view{lang: tc.lang, now: testNow}.Diag(checks, testNow)
		for _, w := range tc.want {
			if !strings.Contains(text, w) {
				t.Errorf("%s lacks %q:\n%s", tc.lang, w, text)
			}
		}
		if tc.lang != "en" && strings.Contains(text, "IPv6 reaches the internet directly") {
			t.Errorf("%s left a known sentence in English", tc.lang)
		}
	}
}

// Every sentence translated here is one the router really writes, verbatim: a sentence reworded in
// the router would otherwise fall back to English without anybody noticing. Read from the router's
// source, beside this package.
func TestDaemonSentencesAreTheRoutersOwn(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "server", "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("the router's source: %v", err)
	}
	var src strings.Builder
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src.Write(raw)
	}
	all := src.String()
	for en, tr := range daemonText {
		if !strings.Contains(all, strconv.Quote(en)) {
			t.Errorf("not a sentence the router writes: %q", en)
		}
		if tr[0] == "" || tr[1] == "" || tr[0] == en || tr[1] == en {
			t.Errorf("untranslated: %q", en)
		}
	}
	for _, p := range daemonPatterns {
		if !strings.Contains(all, strconv.Quote(p.src)) {
			t.Errorf("not a sentence the router writes: %q", p.src)
		}
		sample := strings.ReplaceAll(p.src, "%d", "7")
		switch {
		case strings.HasPrefix(p.src, " "):
			sample = "hybrid" + sample
		case strings.HasSuffix(p.src, " "):
			sample += "5m0s"
		}
		m := p.re.FindStringSubmatch(sample)
		if m == nil {
			t.Errorf("%q does not read the router's own %q", p.re, sample)
			continue
		}
		parts := make([]any, 0, len(m)-1)
		for _, s := range m[1:] {
			parts = append(parts, s)
		}
		for _, f := range []string{p.ru, p.uk} {
			if n := strings.Count(f, "%s"); n != len(m)-1 || strings.Contains(fmt.Sprintf(f, parts...), "%!") {
				t.Errorf("%q takes %d parts, the pattern reads %d", f, n, len(m)-1)
			}
		}
	}
}

// Errors the bot knows by kind are told in the chat's language; the rest keep their words.
func TestErrorTextSpeaksTheChatsLanguage(t *testing.T) {
	ru := view{lang: "ru", now: testNow}
	for _, tc := range []struct {
		err  error
		want string
	}{
		{ErrBusy, "уже выполняется"},
		{fmt.Errorf("refresh: %w", context.DeadlineExceeded), "слишком много времени"},
		{ErrUnavailable, "недоступно на этом роутере"},
		{errors.New("apply: the plan names a missing table"), "apply: the plan names a missing table"},
	} {
		if got := errorText(ru, tc.err); !strings.Contains(got, tc.want) {
			t.Errorf("%v: %q", tc.err, got)
		}
	}
}
