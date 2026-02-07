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

func TestGetSetFlags(t *testing.T) {
	tests := []struct {
		name      string
		value     uint32
		flagNames map[uint32]string
		wantCount int
		wantFlags []string
	}{
		{
			name:      "no flags set",
			value:     0,
			flagNames: EnrollmentFlagNames,
			wantCount: 0,
		},
		{
			name:      "single enrollment flag",
			value:     CT_FLAG_AUTO_ENROLLMENT,
			flagNames: EnrollmentFlagNames,
			wantCount: 1,
			wantFlags: []string{"AUTO_ENROLLMENT"},
		},
		{
			name:      "multiple enrollment flags",
			value:     CT_FLAG_PEND_ALL_REQUESTS | CT_FLAG_PUBLISH_TO_DS | CT_FLAG_AUTO_ENROLLMENT,
			flagNames: EnrollmentFlagNames,
			wantCount: 3,
			wantFlags: []string{"PEND_ALL_REQUESTS", "PUBLISH_TO_DS", "AUTO_ENROLLMENT"},
		},
		{
			name:      "name flags",
			value:     CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT | CT_FLAG_SUBJECT_ALT_REQUIRE_DNS,
			flagNames: NameFlagNames,
			wantCount: 2,
			wantFlags: []string{"ENROLLEE_SUPPLIES_SUBJECT", "SUBJECT_ALT_REQUIRE_DNS"},
		},
		{
			name:      "unknown bits ignored",
			value:     0x80000000 | CT_FLAG_AUTO_ENROLLMENT,
			flagNames: EnrollmentFlagNames,
			wantCount: 1,
			wantFlags: []string{"AUTO_ENROLLMENT"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GetSetFlags(tt.value, tt.flagNames)
			if len(got) != tt.wantCount {
				t.Fatalf("GetSetFlags() returned %d flags, want %d: %v", len(got), tt.wantCount, got)
			}
			for _, want := range tt.wantFlags {
				found := false
				for _, g := range got {
					if g == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("GetSetFlags() missing %q in result %v", want, got)
				}
			}
		})
	}
}
