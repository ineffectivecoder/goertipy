package ldap

import "testing"

func TestSidStringToBinary(t *testing.T) {
	tests := []struct {
		name string
		sid  string
		want string
	}{
		{
			name: "Everyone (S-1-1-0)",
			sid:  "S-1-1-0",
			want: "\\01\\01\\00\\00\\00\\00\\00\\01\\00\\00\\00\\00",
		},
		{
			name: "Local System (S-1-5-18)",
			sid:  "S-1-5-18",
			want: "\\01\\01\\00\\00\\00\\00\\00\\05\\12\\00\\00\\00",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sidStringToBinary(tt.sid)
			if got != tt.want {
				t.Errorf("sidStringToBinary(%q) =\n  %q\nwant\n  %q", tt.sid, got, tt.want)
			}
		})
	}
}

func TestSidStringToBinaryInvalid(t *testing.T) {
	tests := []struct {
		name string
		sid  string
	}{
		{"empty", ""},
		{"no S- prefix", "1-5-18"},
		{"too few parts", "S-1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sidStringToBinary(tt.sid)
			if got != "" {
				t.Errorf("expected empty for invalid SID %q, got %q", tt.sid, got)
			}
		})
	}
}

func TestExtractDomainFromDN(t *testing.T) {
	tests := []struct {
		name string
		dn   string
		want string
	}{
		{
			name: "simple domain",
			dn:   "CN=User,CN=Users,DC=corp,DC=local",
			want: "corp",
		},
		{
			name: "uppercase DC",
			dn:   "CN=Admins,OU=Groups,DC=CONTOSO,DC=COM",
			want: "CONTOSO",
		},
		{
			name: "no DC components",
			dn:   "CN=Test,OU=Something",
			want: "",
		},
		{
			name: "empty",
			dn:   "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDomainFromDN(tt.dn)
			if got != tt.want {
				t.Errorf("extractDomainFromDN(%q) = %q, want %q", tt.dn, got, tt.want)
			}
		})
	}
}

func TestParseHashes(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLM  string
		wantNT  string
		wantErr bool
	}{
		{"empty", "", "", "", false},
		{"NT only", ":aabbccdd", "", "aabbccdd", false},
		{"LM:NT", "aabbccdd:11223344", "aabbccdd", "11223344", false},
		{"invalid format (no colon)", "aabbccdd", "", "", true},
		{"invalid NT hex", ":xyz123", "", "", true},
		{"invalid LM hex", "xyz:aabbccdd", "", "", true},
		{"empty NT", "aabb:", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lm, nt, err := ParseHashes(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseHashes(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if lm != tt.wantLM {
					t.Errorf("LM = %q, want %q", lm, tt.wantLM)
				}
				if nt != tt.wantNT {
					t.Errorf("NT = %q, want %q", nt, tt.wantNT)
				}
			}
		})
	}
}
