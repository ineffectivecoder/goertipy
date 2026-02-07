package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/slacker/goertipy/pkg/adcs"
)

func TestTextFormatterColor(t *testing.T) {
	result := &adcs.FindResult{
		Domain:              "corp.local",
		TotalCAs:            1,
		TotalTemplates:      2,
		VulnerableTemplates: 1,
		CAs: []*adcs.CertificateAuthority{
			{
				CAName:               "DC01\\corp-CA",
				DNSHostName:          "dc01.corp.local",
				CertificateTemplates: []string{"User", "WebServer"},
				Vulnerabilities:      []string{"ESC6"},
				HasWebEnrollment:     true,
			},
		},
		Templates: []*adcs.CertificateTemplate{
			{
				Name:                    "VulnTemplate",
				DisplayName:             "Vulnerable Template",
				SchemaVersion:           2,
				Enabled:                 true,
				EnrolleeSuppliesSubject: true,
				Vulnerabilities:         []string{"ESC1"},
			},
			{
				Name:          "SafeTemplate",
				SchemaVersion: 4,
				Enabled:       false,
			},
		},
	}

	var buf bytes.Buffer
	f := NewTextFormatter(&buf, true)
	if err := f.Format(result); err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	output := buf.String()

	// Check that color codes are present
	if !strings.Contains(output, colorRed) {
		t.Error("expected red color codes in output")
	}
	if !strings.Contains(output, colorGreen) {
		t.Error("expected green color codes in output")
	}
	if !strings.Contains(output, "VULNERABLE") {
		t.Error("expected VULNERABLE marker")
	}
	if !strings.Contains(output, "Enabled") {
		t.Error("expected Enabled status")
	}
	if !strings.Contains(output, "Disabled") {
		t.Error("expected Disabled status")
	}
	if !strings.Contains(output, "Web Enrollment") {
		t.Error("expected Web Enrollment info")
	}
}

func TestTextFormatterNoColor(t *testing.T) {
	result := &adcs.FindResult{
		TotalCAs:  0,
		Templates: []*adcs.CertificateTemplate{},
	}

	var buf bytes.Buffer
	f := NewTextFormatter(&buf, false)
	if err := f.Format(result); err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	output := buf.String()

	// Should NOT contain ANSI escape codes
	if strings.Contains(output, "\033[") {
		t.Error("no-color output should not contain ANSI escape codes")
	}
}

func TestJSONFormatterOutput(t *testing.T) {
	result := &adcs.FindResult{
		Domain:              "test.local",
		TotalCAs:            1,
		TotalTemplates:      1,
		VulnerableTemplates: 1,
		CAs: []*adcs.CertificateAuthority{
			{
				Name:                 "TestCA",
				CAName:               "DC\\TestCA",
				DNSHostName:          "dc.test.local",
				CertificateTemplates: []string{"Tmpl1"},
				Vulnerabilities:      []string{"ESC8"},
				HasWebEnrollment:     true,
			},
		},
		Templates: []*adcs.CertificateTemplate{
			{
				Name:             "Tmpl1",
				Enabled:          true,
				SchemaVersion:    2,
				Vulnerabilities:  []string{"ESC1"},
				IssuancePolicies: []string{"1.2.3"},
			},
		},
	}

	var buf bytes.Buffer
	f := NewJSONFormatter(&buf, true)
	if err := f.Format(result); err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	var out JSONOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if out.Domain != "test.local" {
		t.Errorf("domain = %q, want test.local", out.Domain)
	}
	if len(out.CAs) != 1 {
		t.Fatalf("expected 1 CA, got %d", len(out.CAs))
	}
	if !out.CAs[0].WebEnrollment {
		t.Error("expected web_enrollment = true")
	}
	if len(out.Templates) != 1 {
		t.Fatalf("expected 1 template, got %d", len(out.Templates))
	}
	if !out.Templates[0].Enabled {
		t.Error("expected template enabled = true")
	}
	if len(out.Templates[0].IssuancePolicies) != 1 {
		t.Error("expected 1 issuance policy")
	}
	if out.Summary.VulnerableTemplates != 1 {
		t.Errorf("summary vulnerable = %d, want 1", out.Summary.VulnerableTemplates)
	}
}
