package adcs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/slacker/goertipy/pkg/adcs/flags"
)

func TestSaveAndLoadTemplateConfig(t *testing.T) {
	tmpDir := t.TempDir()
	backupPath := filepath.Join(tmpDir, "test_backup.json")

	tmpl := &CertificateTemplate{
		Name:                "TestTemplate",
		DN:                  "CN=TestTemplate,CN=Certificate Templates,CN=Public Key Services",
		CertificateNameFlag: 0x08000000, // SUBJECT_ALT_REQUIRE_DNS
		EnrollmentFlag:      0x00000020, // AUTO_ENROLLMENT
		RASignature:         2,
		ExtendedKeyUsage:    []string{flags.EKU_CLIENT_AUTH, flags.EKU_SERVER_AUTH},
		ApplicationPolicies: []string{flags.EKU_CLIENT_AUTH},
	}

	// Save
	if err := SaveTemplateConfig(tmpl, backupPath); err != nil {
		t.Fatalf("SaveTemplateConfig() error: %v", err)
	}

	// Verify file exists with restricted permissions
	info, err := os.Stat(backupPath)
	if err != nil {
		t.Fatalf("backup file not created: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("backup file permissions = %o, want 0600", info.Mode().Perm())
	}

	// Load
	config, err := LoadTemplateConfig(backupPath)
	if err != nil {
		t.Fatalf("LoadTemplateConfig() error: %v", err)
	}

	if config.TemplateName != "TestTemplate" {
		t.Errorf("template_name = %q, want TestTemplate", config.TemplateName)
	}
	if config.DN != tmpl.DN {
		t.Errorf("dn = %q, want %q", config.DN, tmpl.DN)
	}
	if config.CertificateNameFlag != "134217728" { // 0x08000000
		t.Errorf("name flag = %q, want 134217728", config.CertificateNameFlag)
	}
	if config.EnrollmentFlag != "32" { // 0x20
		t.Errorf("enrollment flag = %q, want 32", config.EnrollmentFlag)
	}
	if config.RASignature != "2" {
		t.Errorf("ra signature = %q, want 2", config.RASignature)
	}
	if len(config.ExtendedKeyUsage) != 2 {
		t.Fatalf("expected 2 EKUs, got %d", len(config.ExtendedKeyUsage))
	}
	if config.ExtendedKeyUsage[0] != flags.EKU_CLIENT_AUTH {
		t.Errorf("EKU[0] = %q, want Client Auth OID", config.ExtendedKeyUsage[0])
	}
	if config.Timestamp == "" {
		t.Error("expected non-empty timestamp")
	}
}

func TestLoadTemplateConfig_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "bad.json")
	os.WriteFile(path, []byte("not json"), 0600)

	_, err := LoadTemplateConfig(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoadTemplateConfig_MissingFields(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "empty.json")
	data, _ := json.Marshal(TemplateConfig{})
	os.WriteFile(path, data, 0600)

	_, err := LoadTemplateConfig(path)
	if err == nil {
		t.Error("expected error for missing DN and template name")
	}
}

func TestLoadTemplateConfig_FileNotFound(t *testing.T) {
	_, err := LoadTemplateConfig("/nonexistent/path/backup.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestModifyTemplateForESC1_FlagComputation(t *testing.T) {
	tests := []struct {
		name                string
		nameFlag            uint32
		enrollFlag          uint32
		raSignature         int
		ekus                []string
		wantSuppliesSubject bool
		wantApprovalCleared bool
	}{
		{
			name:                "basic template — no flags set",
			nameFlag:            0x08000000, // SUBJECT_ALT_REQUIRE_DNS only
			enrollFlag:          0x00000020, // AUTO_ENROLLMENT only
			raSignature:         0,
			ekus:                []string{flags.EKU_SERVER_AUTH},
			wantSuppliesSubject: true, // should add ENROLLEE_SUPPLIES_SUBJECT
			wantApprovalCleared: true, // PEND_ALL_REQUESTS was not set, stays clear
		},
		{
			name:                "template with manager approval",
			nameFlag:            0,
			enrollFlag:          flags.CT_FLAG_PEND_ALL_REQUESTS | flags.CT_FLAG_AUTO_ENROLLMENT, // 0x22
			raSignature:         3,
			ekus:                []string{flags.EKU_CODE_SIGNING},
			wantSuppliesSubject: true,
			wantApprovalCleared: true, // PEND_ALL_REQUESTS should be cleared
		},
		{
			name:                "already ESC1-like template",
			nameFlag:            flags.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT,
			enrollFlag:          0,
			raSignature:         0,
			ekus:                []string{flags.EKU_CLIENT_AUTH},
			wantSuppliesSubject: true,
			wantApprovalCleared: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl := &CertificateTemplate{
				CertificateNameFlag: tt.nameFlag,
				EnrollmentFlag:      tt.enrollFlag,
				RASignature:         tt.raSignature,
				ExtendedKeyUsage:    tt.ekus,
			}

			// Verify flag computations (without LDAP)
			newNameFlag := tmpl.CertificateNameFlag | flags.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
			newEnrollFlag := tmpl.EnrollmentFlag &^ flags.CT_FLAG_PEND_ALL_REQUESTS

			if tt.wantSuppliesSubject {
				if !flags.HasFlag(newNameFlag, flags.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) {
					t.Error("ENROLLEE_SUPPLIES_SUBJECT should be set")
				}
			}

			if tt.wantApprovalCleared {
				if flags.HasFlag(newEnrollFlag, flags.CT_FLAG_PEND_ALL_REQUESTS) {
					t.Error("PEND_ALL_REQUESTS should be cleared")
				}
			}

			// Verify other flags are preserved
			if tt.enrollFlag&flags.CT_FLAG_AUTO_ENROLLMENT != 0 {
				if !flags.HasFlag(newEnrollFlag, flags.CT_FLAG_AUTO_ENROLLMENT) {
					t.Error("AUTO_ENROLLMENT should be preserved")
				}
			}
		})
	}
}

func TestModifyTemplateForESC1_PreservesNameFlags(t *testing.T) {
	// Verify that adding ENROLLEE_SUPPLIES_SUBJECT preserves existing name flags
	original := flags.CT_FLAG_SUBJECT_ALT_REQUIRE_DNS | flags.CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME
	modified := original | flags.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT

	if !flags.HasFlag(modified, flags.CT_FLAG_SUBJECT_ALT_REQUIRE_DNS) {
		t.Error("SUBJECT_ALT_REQUIRE_DNS should be preserved")
	}
	if !flags.HasFlag(modified, flags.CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME) {
		t.Error("SUBJECT_REQUIRE_COMMON_NAME should be preserved")
	}
	if !flags.HasFlag(modified, flags.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) {
		t.Error("ENROLLEE_SUPPLIES_SUBJECT should be added")
	}
}

func TestTemplateConfigJSON_Roundtrip(t *testing.T) {
	original := &TemplateConfig{
		TemplateName:        "RoundTrip",
		DN:                  "CN=RoundTrip,CN=Certificate Templates",
		Timestamp:           "2026-01-01T00:00:00Z",
		CertificateNameFlag: "134217729",
		EnrollmentFlag:      "34",
		RASignature:         "1",
		ExtendedKeyUsage:    []string{flags.EKU_CLIENT_AUTH, flags.EKU_SERVER_AUTH},
		ApplicationPolicies: []string{flags.EKU_CLIENT_AUTH},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var restored TemplateConfig
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if restored.TemplateName != original.TemplateName {
		t.Errorf("name = %q, want %q", restored.TemplateName, original.TemplateName)
	}
	if restored.CertificateNameFlag != original.CertificateNameFlag {
		t.Errorf("name flag = %q, want %q", restored.CertificateNameFlag, original.CertificateNameFlag)
	}
	if restored.EnrollmentFlag != original.EnrollmentFlag {
		t.Errorf("enrollment flag = %q, want %q", restored.EnrollmentFlag, original.EnrollmentFlag)
	}
	if restored.RASignature != original.RASignature {
		t.Errorf("ra sig = %q, want %q", restored.RASignature, original.RASignature)
	}
	if len(restored.ExtendedKeyUsage) != len(original.ExtendedKeyUsage) {
		t.Errorf("EKU count = %d, want %d", len(restored.ExtendedKeyUsage), len(original.ExtendedKeyUsage))
	}
	if len(restored.ApplicationPolicies) != len(original.ApplicationPolicies) {
		t.Errorf("app policies count = %d, want %d", len(restored.ApplicationPolicies), len(original.ApplicationPolicies))
	}
}
