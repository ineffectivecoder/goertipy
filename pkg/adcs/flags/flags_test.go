package flags

import "testing"

func TestIsAuthenticationEKU(t *testing.T) {
	tests := []struct {
		oid  string
		want bool
	}{
		{EKU_CLIENT_AUTH, true},
		{EKU_SMART_CARD_LOGON, true},
		{EKU_PKINIT_CLIENT_AUTH, true},
		{EKU_ANY_PURPOSE, true},
		{EKU_SERVER_AUTH, false},
		{EKU_CODE_SIGNING, false},
		{EKU_CERTIFICATE_REQUEST_AGENT, false},
		{"1.2.3.4.5", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.oid, func(t *testing.T) {
			if got := IsAuthenticationEKU(tt.oid); got != tt.want {
				t.Errorf("IsAuthenticationEKU(%q) = %v, want %v", tt.oid, got, tt.want)
			}
		})
	}
}

func TestHasFlag(t *testing.T) {
	tests := []struct {
		name  string
		value uint32
		flag  uint32
		want  bool
	}{
		{"flag set", 0x00000003, CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT, true},
		{"flag not set", 0x00000002, CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT, false},
		{"exact flag", CT_FLAG_PEND_ALL_REQUESTS, CT_FLAG_PEND_ALL_REQUESTS, true},
		{"zero value", 0, CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT, false},
		{"all bits", 0xFFFFFFFF, CT_FLAG_NO_SECURITY_EXTENSION, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasFlag(tt.value, tt.flag); got != tt.want {
				t.Errorf("HasFlag(0x%x, 0x%x) = %v, want %v", tt.value, tt.flag, got, tt.want)
			}
		})
	}
}
