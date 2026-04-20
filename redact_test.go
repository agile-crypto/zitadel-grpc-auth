package auth

import (
	"strings"
	"testing"
)

func TestRedactToken(t *testing.T) {
	cases := []struct {
		token    string
		mustHave []string
	}{
		{"", []string{"empty"}},
		{"abc", []string{"***", "len=3"}},
		{"abcdefgh", []string{"********", "len=8"}},
		{"abcdefghij", []string{"abcd", "ghij", "**", "len=10"}},
	}
	for _, tc := range cases {
		got := RedactToken(tc.token)
		for _, m := range tc.mustHave {
			if !strings.Contains(got, m) {
				t.Errorf("RedactToken(%q)=%q missing %q", tc.token, got, m)
			}
		}
		if strings.Contains(got, "cdef") && len(tc.token) > 8 {
			t.Errorf("RedactToken leaked middle of token: %q", got)
		}
	}
}
