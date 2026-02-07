package adcs

import (
	"testing"
)

func TestNormalizeSerialNumber(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"plain hex", "abc123", "ABC123"},
		{"with 0x prefix", "0xabc123", "ABC123"},
		{"with 0X prefix", "0XABC123", "ABC123"},
		{"with colons", "ab:cd:ef:01", "ABCDEF01"},
		{"with spaces", "ab cd ef 01", "ABCDEF01"},
		{"mixed separators", "0x ab:cd ef:01", "ABCDEF01"},
		{"already uppercase", "ABCDEF", "ABCDEF"},
		{"empty string", "", ""},
		{"realistic serial", "61:00:00:00:0a:28:47:6e:88:96:7e:11:3c:00:00:00:00:00:0a", "610000000A28476E88967E113C00000000000A"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeSerialNumber(tt.input)
			if got != tt.expected {
				t.Errorf("NormalizeSerialNumber(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestRevocationReasonFromString(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  uint32
		expectErr bool
	}{
		{"unspecified", "unspecified", RevokeReasonUnspecified, false},
		{"by number 0", "0", RevokeReasonUnspecified, false},
		{"keycompromise", "keycompromise", RevokeReasonKeyCompromise, false},
		{"key-compromise kebab", "key-compromise", RevokeReasonKeyCompromise, false},
		{"key_compromise snake", "key_compromise", RevokeReasonKeyCompromise, false},
		{"by number 1", "1", RevokeReasonKeyCompromise, false},
		{"cacompromise", "cacompromise", RevokeReasonCACompromise, false},
		{"by number 2", "2", RevokeReasonCACompromise, false},
		{"affiliationchanged", "affiliationchanged", RevokeReasonAffiliationChanged, false},
		{"by number 3", "3", RevokeReasonAffiliationChanged, false},
		{"superseded", "superseded", RevokeReasonSuperseded, false},
		{"by number 4", "4", RevokeReasonSuperseded, false},
		{"cessation", "cessation", RevokeReasonCessationOfOp, false},
		{"by number 5", "5", RevokeReasonCessationOfOp, false},
		{"hold", "hold", RevokeReasonCertificateHold, false},
		{"certificate-hold", "certificate-hold", RevokeReasonCertificateHold, false},
		{"by number 6", "6", RevokeReasonCertificateHold, false},
		{"removefromcrl", "removefromcrl", RevokeReasonRemoveFromCRL, false},
		{"by number 8", "8", RevokeReasonRemoveFromCRL, false},
		{"unhold", "unhold", RevokeReasonReleaseFromHold, false},
		{"release", "release", RevokeReasonReleaseFromHold, false},
		{"case insensitive", "KeyCompromise", RevokeReasonKeyCompromise, false},
		{"with spaces", "  superseded  ", RevokeReasonSuperseded, false},
		{"invalid string", "invalid", 0, true},
		{"invalid number", "99", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RevocationReasonFromString(tt.input)
			if tt.expectErr {
				if err == nil {
					t.Errorf("RevocationReasonFromString(%q) expected error, got %d", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Errorf("RevocationReasonFromString(%q) unexpected error: %v", tt.input, err)
				return
			}
			if got != tt.expected {
				t.Errorf("RevocationReasonFromString(%q) = %d, want %d", tt.input, got, tt.expected)
			}
		})
	}
}

func TestRevocationReasonNames(t *testing.T) {
	// Verify all constants have names
	reasons := []uint32{
		RevokeReasonUnspecified,
		RevokeReasonKeyCompromise,
		RevokeReasonCACompromise,
		RevokeReasonAffiliationChanged,
		RevokeReasonSuperseded,
		RevokeReasonCessationOfOp,
		RevokeReasonCertificateHold,
		RevokeReasonRemoveFromCRL,
		RevokeReasonReleaseFromHold,
	}

	for _, r := range reasons {
		name, ok := RevocationReasonNames[r]
		if !ok {
			t.Errorf("RevocationReasonNames missing entry for reason code %d", r)
		}
		if name == "" {
			t.Errorf("RevocationReasonNames[%d] is empty", r)
		}
	}
}
