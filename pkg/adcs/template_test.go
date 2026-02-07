package adcs

import (
	"testing"

	"github.com/slacker/goertipy/pkg/adcs/flags"
)

func TestAnalyzeVulnerabilities_ESC1(t *testing.T) {
	tmpl := &CertificateTemplate{
		EnrolleeSuppliesSubject: true,
		HasAuthenticationEKU:    true,
		RequiresManagerApproval: false,
		RASignature:             0,
		SchemaVersion:           2,
	}
	tmpl.analyzeVulnerabilities()

	if !contains(tmpl.Vulnerabilities, "ESC1") {
		t.Error("expected ESC1 vulnerability")
	}
}

func TestAnalyzeVulnerabilities_ESC1_BlockedByApproval(t *testing.T) {
	tmpl := &CertificateTemplate{
		EnrolleeSuppliesSubject: true,
		HasAuthenticationEKU:    true,
		RequiresManagerApproval: true,
		RASignature:             0,
	}
	tmpl.analyzeVulnerabilities()

	if contains(tmpl.Vulnerabilities, "ESC1") {
		t.Error("ESC1 should not trigger when manager approval is required")
	}
}

func TestAnalyzeVulnerabilities_ESC2(t *testing.T) {
	tmpl := &CertificateTemplate{
		ExtendedKeyUsage:        []string{}, // No EKUs = Any Purpose
		RequiresManagerApproval: false,
		RASignature:             0,
		SchemaVersion:           2,
	}
	tmpl.HasAuthenticationEKU = tmpl.hasAuthEKU()
	tmpl.analyzeVulnerabilities()

	if !contains(tmpl.Vulnerabilities, "ESC2") {
		t.Error("expected ESC2 vulnerability for no-EKU template")
	}
}

func TestAnalyzeVulnerabilities_ESC3(t *testing.T) {
	tmpl := &CertificateTemplate{
		ExtendedKeyUsage:        []string{flags.EKU_CERTIFICATE_REQUEST_AGENT},
		RequiresManagerApproval: false,
		RASignature:             0,
	}
	tmpl.HasAuthenticationEKU = tmpl.hasAuthEKU()
	tmpl.analyzeVulnerabilities()

	if !contains(tmpl.Vulnerabilities, "ESC3") {
		t.Errorf("expected ESC3 vulnerability, got %v", tmpl.Vulnerabilities)
	}
}

func TestAnalyzeVulnerabilities_ESC9(t *testing.T) {
	tmpl := &CertificateTemplate{
		NoSecurityExtension:     true,
		EnrolleeSuppliesSubject: true,
	}
	tmpl.analyzeVulnerabilities()

	if !contains(tmpl.Vulnerabilities, "ESC9") {
		t.Error("expected ESC9 vulnerability")
	}
}

func TestAnalyzeVulnerabilities_ESC13(t *testing.T) {
	tmpl := &CertificateTemplate{
		IssuancePolicies:        []string{"1.3.6.1.4.1.311.21.8.some.oid"},
		HasAuthenticationEKU:    true,
		RequiresManagerApproval: false,
		RASignature:             0,
	}
	tmpl.analyzeVulnerabilities()

	if !contains(tmpl.Vulnerabilities, "ESC13") {
		t.Error("expected ESC13 vulnerability")
	}
}

func TestAnalyzeVulnerabilities_ESC15(t *testing.T) {
	tmpl := &CertificateTemplate{
		SchemaVersion:           1,
		EnrolleeSuppliesSubject: true,
	}
	tmpl.analyzeVulnerabilities()

	if !contains(tmpl.Vulnerabilities, "ESC15") {
		t.Error("expected ESC15 vulnerability")
	}
}

func TestAnalyzeVulnerabilities_NoVulns(t *testing.T) {
	tmpl := &CertificateTemplate{
		EnrolleeSuppliesSubject: false,
		ExtendedKeyUsage:        []string{flags.EKU_SERVER_AUTH},
		RequiresManagerApproval: true,
		RASignature:             1,
		SchemaVersion:           4,
	}
	tmpl.HasAuthenticationEKU = tmpl.hasAuthEKU()
	tmpl.analyzeVulnerabilities()

	if len(tmpl.Vulnerabilities) > 0 {
		t.Errorf("expected no vulnerabilities, got %v", tmpl.Vulnerabilities)
	}
}

func TestHasAuthEKU(t *testing.T) {
	tests := []struct {
		name string
		ekus []string
		want bool
	}{
		{"no EKUs (any purpose)", nil, true},
		{"client auth", []string{flags.EKU_CLIENT_AUTH}, true},
		{"smart card", []string{flags.EKU_SMART_CARD_LOGON}, true},
		{"any purpose explicit", []string{flags.EKU_ANY_PURPOSE}, true},
		{"server auth only", []string{flags.EKU_SERVER_AUTH}, false},
		{"code signing only", []string{flags.EKU_CODE_SIGNING}, false},
		{"mixed with client auth", []string{flags.EKU_SERVER_AUTH, flags.EKU_CLIENT_AUTH}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl := &CertificateTemplate{ExtendedKeyUsage: tt.ekus}
			if got := tmpl.hasAuthEKU(); got != tt.want {
				t.Errorf("hasAuthEKU() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseFiletimeDuration(t *testing.T) {
	tests := []struct {
		name string
		days int
		want string
	}{
		{"1 year", 365, "1 years"},
		{"2 years", 730, "2 years"},
		{"6 weeks", 42, "6 weeks"},
		{"5 days", 5, "5 days"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a FILETIME duration: negative value in 100ns intervals
			seconds := int64(tt.days) * 86400
			val := -seconds * 10000000

			data := make([]byte, 8)
			// Store as uint64 (two's complement negative)
			uval := uint64(val)
			for i := 0; i < 8; i++ {
				data[i] = byte(uval >> (i * 8))
			}

			got := parseFiletimeDuration(data)
			if got != tt.want {
				t.Errorf("parseFiletimeDuration(%d days) = %q, want %q", tt.days, got, tt.want)
			}
		})
	}
}

func TestParseFiletimeDurationShortData(t *testing.T) {
	got := parseFiletimeDuration([]byte{1, 2, 3})
	if got != "" {
		t.Errorf("expected empty for short data, got %q", got)
	}
}

func TestIsVulnerable(t *testing.T) {
	tmpl := &CertificateTemplate{}
	if tmpl.IsVulnerable() {
		t.Error("empty template should not be vulnerable")
	}
	tmpl.Vulnerabilities = []string{"ESC1"}
	if !tmpl.IsVulnerable() {
		t.Error("template with ESC1 should be vulnerable")
	}
}

func TestGetEKUNames(t *testing.T) {
	tmpl := &CertificateTemplate{
		ExtendedKeyUsage: []string{flags.EKU_CLIENT_AUTH, "1.2.3.4.5"},
	}
	names := tmpl.GetEKUNames()
	if len(names) != 2 {
		t.Fatalf("expected 2 names, got %d", len(names))
	}
	if names[0] != "Client Authentication" {
		t.Errorf("first EKU name = %q, want \"Client Authentication\"", names[0])
	}
	if names[1] != "1.2.3.4.5" {
		t.Errorf("unknown EKU should return OID, got %q", names[1])
	}
}

func TestGetEKUNamesEmpty(t *testing.T) {
	tmpl := &CertificateTemplate{}
	names := tmpl.GetEKUNames()
	if len(names) != 1 || names[0] != "(No EKUs - Any Purpose)" {
		t.Errorf("empty EKUs should return Any Purpose, got %v", names)
	}
}

func TestHasExplicitClientAuth(t *testing.T) {
	tests := []struct {
		name     string
		ekus     []string
		policies []string
		want     bool
	}{
		{
			name: "client auth in EKU",
			ekus: []string{flags.EKU_CLIENT_AUTH},
			want: true,
		},
		{
			name:     "client auth in application policies",
			ekus:     []string{flags.EKU_SERVER_AUTH},
			policies: []string{flags.EKU_CLIENT_AUTH},
			want:     true,
		},
		{
			name: "server auth only",
			ekus: []string{flags.EKU_SERVER_AUTH},
			want: false,
		},
		{
			name: "no EKUs",
			ekus: nil,
			want: false,
		},
		{
			name: "any purpose is not explicit client auth",
			ekus: []string{flags.EKU_ANY_PURPOSE},
			want: false,
		},
		{
			name: "mixed EKUs with client auth",
			ekus: []string{flags.EKU_SERVER_AUTH, flags.EKU_CODE_SIGNING, flags.EKU_CLIENT_AUTH},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl := &CertificateTemplate{
				ExtendedKeyUsage:    tt.ekus,
				ApplicationPolicies: tt.policies,
			}
			if got := tmpl.hasExplicitClientAuth(); got != tt.want {
				t.Errorf("hasExplicitClientAuth() = %v, want %v", got, tt.want)
			}
		})
	}
}

func contains(s []string, v string) bool {
	for _, item := range s {
		if item == v {
			return true
		}
	}
	return false
}
