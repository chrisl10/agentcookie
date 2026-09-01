package livecdp

import (
	"testing"

	"github.com/chromedp/cdproto/network"
)

func TestExpectedCookieHost(t *testing.T) {
	tests := []struct {
		param *network.CookieParam
		want  string
	}{
		{param: &network.CookieParam{Domain: ".Example.COM"}, want: "example.com"},
		{param: &network.CookieParam{URL: "https://app.Example.COM/path"}, want: "app.example.com"},
	}
	for _, tc := range tests {
		if got := expectedCookieHost(tc.param); got != tc.want {
			t.Fatalf("expected %q, got %q", tc.want, got)
		}
	}
}
