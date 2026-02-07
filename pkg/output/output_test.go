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
		Domain:               "test.local",
		TotalCAs:             1,
		TotalTemplates:       1,
		VulnerableTemplates:  1,
		ExploitableTemplates: 1,
		ExploitableESCs:      []string{"ESC1"},
		CAs: []*adcs.CertificateAuthority{
			{
				Name:                         "TestCA",
				CAName:                       "DC\\TestCA",
				DNSHostName:                  "dc.test.local",
				CertificateTemplates:         []string{"Tmpl1"},
				Vulnerabilities:              []string{"ESC8"},
				HasWebEnrollment:             true,
				EnrollmentEndpoints:          []string{"http://dc.test.local/certsrv"},
				ManageCAPrincipals:           []string{"CORP\\Domain Admins"},
				ManageCertificatesPrincipals: []string{"CORP\\Enterprise Admins"},
			},
		},
		Templates: []*adcs.CertificateTemplate{
			{
				Name:                 "Tmpl1",
				Enabled:              true,
				SchemaVersion:        2,
				Vulnerabilities:      []string{"ESC1"},
				IssuancePolicies:     []string{"1.2.3"},
				PublishedBy:          []string{"DC\\TestCA"},
				PrivateKeyExportable: true,
				HasClientAuthEKU:     true,
				Exploitability:       "Exploitable",
				EnrollmentFlagNames:  []string{"AUTO_ENROLLMENT"},
				NameFlagNames:        []string{"ENROLLEE_SUPPLIES_SUBJECT"},
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
	if len(out.CAs[0].EnrollmentEndpoints) != 1 {
		t.Error("expected 1 enrollment endpoint")
	}
	if len(out.CAs[0].ManageCA) != 1 {
		t.Error("expected 1 ManageCA principal")
	}
	if len(out.CAs[0].ManageCertificates) != 1 {
		t.Error("expected 1 ManageCertificates principal")
	}
	if len(out.Templates) != 1 {
		t.Fatalf("expected 1 template, got %d", len(out.Templates))
	}
	tmpl := out.Templates[0]
	if !tmpl.Enabled {
		t.Error("expected template enabled = true")
	}
	if !tmpl.PrivateKeyExportable {
		t.Error("expected private_key_exportable = true")
	}
	if !tmpl.HasClientAuthEKU {
		t.Error("expected has_client_auth_eku = true")
	}
	if tmpl.Exploitability != "Exploitable" {
		t.Errorf("exploitability = %q, want Exploitable", tmpl.Exploitability)
	}
	if len(tmpl.PublishedBy) != 1 {
		t.Error("expected 1 published_by CA")
	}
	if len(tmpl.EnrollmentFlagNames) != 1 {
		t.Error("expected 1 enrollment flag name")
	}
	if len(tmpl.IssuancePolicies) != 1 {
		t.Error("expected 1 issuance policy")
	}
	if out.Summary.VulnerableTemplates != 1 {
		t.Errorf("summary vulnerable = %d, want 1", out.Summary.VulnerableTemplates)
	}
	if out.Summary.ExploitableTemplates != 1 {
		t.Errorf("summary exploitable = %d, want 1", out.Summary.ExploitableTemplates)
	}
	if len(out.Summary.ExploitableESCs) != 1 {
		t.Error("expected 1 exploitable ESC in summary")
	}
}

func TestTextFormatterEnhancedFields(t *testing.T) {
	result := &adcs.FindResult{
		Domain:               "corp.local",
		TotalCAs:             1,
		TotalTemplates:       1,
		VulnerableTemplates:  1,
		ExploitableTemplates: 1,
		ExploitableESCs:      []string{"ESC1"},
		CAs: []*adcs.CertificateAuthority{
			{
				CAName:                       "DC01\\corp-CA",
				DNSHostName:                  "dc01.corp.local",
				CertificateTemplates:         []string{"VulnTmpl"},
				EnrollmentEndpoints:          []string{"https://dc01.corp.local/certsrv"},
				ManageCAPrincipals:           []string{"CORP\\Domain Admins"},
				ManageCertificatesPrincipals: []string{"CORP\\Cert Publishers"},
			},
		},
		Templates: []*adcs.CertificateTemplate{
			{
				Name:                    "VulnTmpl",
				Enabled:                 true,
				SchemaVersion:           2,
				EnrolleeSuppliesSubject: true,
				PrivateKeyExportable:    true,
				HasClientAuthEKU:        true,
				PublishedBy:             []string{"DC01\\corp-CA"},
				Exploitability:          "Exploitable",
				Vulnerabilities:         []string{"ESC1"},
				EnrollmentFlagNames:     []string{"AUTO_ENROLLMENT"},
				NameFlagNames:           []string{"ENROLLEE_SUPPLIES_SUBJECT"},
			},
		},
	}

	var buf bytes.Buffer
	f := NewTextFormatter(&buf, false) // no color for easy string matching
	if err := f.Format(result); err != nil {
		t.Fatalf("Format() error: %v", err)
	}

	output := buf.String()

	// CA fields
	if !strings.Contains(output, "ManageCA") {
		t.Error("expected ManageCA in output")
	}
	if !strings.Contains(output, "ManageCertificates") {
		t.Error("expected ManageCertificates in output")
	}
	if !strings.Contains(output, "Enrollment Endpoints") {
		t.Error("expected Enrollment Endpoints in output")
	}

	// Template fields
	if !strings.Contains(output, "Private Key Exportable") {
		t.Error("expected Private Key Exportable in output")
	}
	if !strings.Contains(output, "Published By") {
		t.Error("expected Published By in output")
	}
	if !strings.Contains(output, "ENROLLEE_SUPPLIES_SUBJECT") {
		t.Error("expected ENROLLEE_SUPPLIES_SUBJECT in output")
	}
	if !strings.Contains(output, "EXPLOITABLE") {
		t.Error("expected EXPLOITABLE severity label in output")
	}
	if !strings.Contains(output, "Enrollment Flags") {
		t.Error("expected Enrollment Flags in output")
	}

	// Summary
	if !strings.Contains(output, "Directly Exploitable") {
		t.Error("expected Directly Exploitable in summary")
	}
}
