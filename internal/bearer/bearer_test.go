package bearer

import (
	"testing"

	"google.golang.org/grpc/metadata"
)

func TestFromIncomingMetadata(t *testing.T) {
	cases := []struct {
		name string
		md   metadata.MD
		want string
	}{
		{"nil md", nil, ""},
		{"missing", metadata.Pairs("other", "v"), ""},
		{"empty value", metadata.MD{"authorization": []string{""}}, ""},
		{"missing scheme", metadata.Pairs("authorization", "abc"), ""},
		{"bearer lowercase", metadata.Pairs("authorization", "bearer abc"), "abc"},
		{"bearer mixed case", metadata.Pairs("authorization", "BeArEr abc"), "abc"},
		{"trims whitespace", metadata.Pairs("authorization", "Bearer   abc  "), "abc"},
		{"basic auth ignored", metadata.Pairs("authorization", "Basic dXNlcjpwYXNz"), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FromIncomingMetadata(tc.md); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}
