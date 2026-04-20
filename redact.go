package auth

import "fmt"

// RedactToken returns a safe-to-log representation of a bearer token: the
// first 4 and last 4 characters with the middle masked, plus the length.
// For tokens of 8 characters or fewer the entire value is masked.
//
// This is the only "logging" helper the module ships, deliberately: the
// module never logs tokens itself. Applications that want to log token
// activity (for debugging) should pipe through this helper.
func RedactToken(token string) string {
	const tail = 4
	n := len(token)
	if n == 0 {
		return "(empty)"
	}
	if n <= 2*tail {
		return fmt.Sprintf("%s (len=%d)", maskAll(n), n)
	}
	return fmt.Sprintf("%s%s%s (len=%d)", token[:tail], maskN(n-2*tail), token[n-tail:], n)
}

func maskAll(n int) string { return maskN(n) }

func maskN(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = '*'
	}
	return string(b)
}
