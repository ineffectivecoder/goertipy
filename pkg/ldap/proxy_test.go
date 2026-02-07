package ldap

import (
	"testing"
)

func TestParseProxyURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"empty string", "", "", false},
		{"full socks5 url", "socks5://127.0.0.1:1080", "socks5://127.0.0.1:1080", false},
		{"socks5h url", "socks5h://10.0.0.1:9050", "socks5h://10.0.0.1:9050", false},
		{"host:port only", "127.0.0.1:1080", "socks5://127.0.0.1:1080", false},
		{"http proxy", "http://proxy.corp.local:8080", "http://proxy.corp.local:8080", false},
		{"https proxy", "https://proxy.corp.local:8443", "https://proxy.corp.local:8443", false},
		{"unsupported scheme", "ftp://proxy:21", "", true},
		{"missing port", "socks5://127.0.0.1", "", true},
		{"missing host", "socks5://", "", true},
		{"socks4 url", "socks4://127.0.0.1:1080", "socks4://127.0.0.1:1080", false},
		{"socks4a url", "socks4a://127.0.0.1:1080", "socks4a://127.0.0.1:1080", false},
		{"with auth", "socks5://user:pass@127.0.0.1:1080", "socks5://user:pass@127.0.0.1:1080", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseProxyURL(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseProxyURL(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ParseProxyURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
