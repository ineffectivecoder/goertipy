package output

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/slacker/goertipy/pkg/adcs"
)

// JSONFormatter outputs results in JSON format
type JSONFormatter struct {
	Writer io.Writer
	Indent bool
}

// NewJSONFormatter creates a new JSON formatter
func NewJSONFormatter(w io.Writer, indent bool) *JSONFormatter {
	return &JSONFormatter{Writer: w, Indent: indent}
}

// JSONOutput is the JSON structure for output
type JSONOutput struct {
	Domain    string                      `json:"domain"`
	CAs       []*JSONCertificateAuthority `json:"certificate_authorities"`
	Templates []*JSONCertificateTemplate  `json:"certificate_templates"`
	Summary   JSONSummary                 `json:"summary"`
}

// JSONCertificateAuthority is the JSON structure for a CA
type JSONCertificateAuthority struct {
	Name                 string   `json:"name"`
	CAName               string   `json:"ca_name"`
	DNSHostName          string   `json:"dns_hostname"`
	Subject              string   `json:"subject,omitempty"`
	SerialNumber         string   `json:"serial_number,omitempty"`
	NotBefore            string   `json:"not_before,omitempty"`
	NotAfter             string   `json:"not_after,omitempty"`
	WebEnrollment        bool     `json:"web_enrollment"`
	EnrollmentEndpoints  []string `json:"enrollment_endpoints,omitempty"`
	ManageCA             []string `json:"manage_ca,omitempty"`
	ManageCertificates   []string `json:"manage_certificates,omitempty"`
	CertificateTemplates []string `json:"certificate_templates"`
	Vulnerabilities      []string `json:"vulnerabilities,omitempty"`
}

// JSONCertificateTemplate is the JSON structure for a template
type JSONCertificateTemplate struct {
	Name                           string           `json:"name"`
	DisplayName                    string           `json:"display_name"`
	SchemaVersion                  int              `json:"schema_version"`
	Enabled                        bool             `json:"enabled"`
	PublishedBy                    []string         `json:"published_by,omitempty"`
	ValidityPeriod                 string           `json:"validity_period,omitempty"`
	ExtendedKeyUsage               []string         `json:"extended_key_usage"`
	HasClientAuthEKU               bool             `json:"has_client_auth_eku"`
	IssuancePolicies               []string         `json:"issuance_policies,omitempty"`
	EnrolleeSuppliesSubject        bool             `json:"enrollee_supplies_subject"`
	EnrolleeSuppliesSubjectAltName bool             `json:"enrollee_supplies_subject_alt_name"`
	RequiresManagerApproval        bool             `json:"requires_manager_approval"`
	AuthorizedSignatures           int              `json:"authorized_signatures"`
	NoSecurityExtension            bool             `json:"no_security_extension"`
	PrivateKeyExportable           bool             `json:"private_key_exportable"`
	EnrollmentFlagNames            []string         `json:"enrollment_flags,omitempty"`
	NameFlagNames                  []string         `json:"name_flags,omitempty"`
	Exploitability                 string           `json:"exploitability,omitempty"`
	Permissions                    *JSONPermissions `json:"permissions,omitempty"`
	Vulnerabilities                []string         `json:"vulnerabilities,omitempty"`
}

// JSONPermissions is the JSON structure for template permissions
type JSONPermissions struct {
	Owner             string   `json:"owner,omitempty"`
	EnrollmentRights  []string `json:"enrollment_rights,omitempty"`
	FullControl       []string `json:"full_control,omitempty"`
	WriteOwner        []string `json:"write_owner,omitempty"`
	WriteDACL         []string `json:"write_dacl,omitempty"`
	WriteProperty     []string `json:"write_property,omitempty"`
	AllExtendedRights []string `json:"all_extended_rights,omitempty"`
}

// JSONSummary is the JSON structure for summary
type JSONSummary struct {
	TotalCAs             int      `json:"total_cas"`
	TotalTemplates       int      `json:"total_templates"`
	VulnerableTemplates  int      `json:"vulnerable_templates"`
	ExploitableTemplates int      `json:"exploitable_templates"`
	ConditionalTemplates int      `json:"conditional_templates"`
	ExploitableESCs      []string `json:"exploitable_escs,omitempty"`
}

// Format outputs the find results as JSON
func (f *JSONFormatter) Format(result *adcs.FindResult) error {
	output := JSONOutput{
		Domain: result.Domain,
		Summary: JSONSummary{
			TotalCAs:             result.TotalCAs,
			TotalTemplates:       result.TotalTemplates,
			VulnerableTemplates:  result.VulnerableTemplates,
			ExploitableTemplates: result.ExploitableTemplates,
			ConditionalTemplates: result.ConditionalTemplates,
			ExploitableESCs:      result.ExploitableESCs,
		},
	}

	// Convert CAs
	for _, ca := range result.CAs {
		jsonCA := &JSONCertificateAuthority{
			Name:                 ca.Name,
			CAName:               ca.CAName,
			DNSHostName:          ca.DNSHostName,
			Subject:              ca.Subject,
			SerialNumber:         ca.SerialNumber,
			WebEnrollment:        ca.HasWebEnrollment,
			EnrollmentEndpoints:  ca.EnrollmentEndpoints,
			ManageCA:             ca.ManageCAPrincipals,
			ManageCertificates:   ca.ManageCertificatesPrincipals,
			CertificateTemplates: ca.CertificateTemplates,
			Vulnerabilities:      ca.Vulnerabilities,
		}
		if !ca.NotBefore.IsZero() {
			jsonCA.NotBefore = ca.NotBefore.Format("2006-01-02T15:04:05Z")
		}
		if !ca.NotAfter.IsZero() {
			jsonCA.NotAfter = ca.NotAfter.Format("2006-01-02T15:04:05Z")
		}
		output.CAs = append(output.CAs, jsonCA)
	}

	// Convert templates
	for _, tmpl := range result.Templates {
		jsonTmpl := &JSONCertificateTemplate{
			Name:                           tmpl.Name,
			DisplayName:                    tmpl.DisplayName,
			SchemaVersion:                  tmpl.SchemaVersion,
			Enabled:                        tmpl.Enabled,
			PublishedBy:                    tmpl.PublishedBy,
			ValidityPeriod:                 tmpl.ValidityPeriod,
			ExtendedKeyUsage:               tmpl.ExtendedKeyUsage,
			HasClientAuthEKU:               tmpl.HasClientAuthEKU,
			IssuancePolicies:               tmpl.IssuancePolicies,
			EnrolleeSuppliesSubject:        tmpl.EnrolleeSuppliesSubject,
			EnrolleeSuppliesSubjectAltName: tmpl.EnrolleeSuppliesSubjectAltName,
			RequiresManagerApproval:        tmpl.RequiresManagerApproval,
			AuthorizedSignatures:           tmpl.RASignature,
			NoSecurityExtension:            tmpl.NoSecurityExtension,
			PrivateKeyExportable:           tmpl.PrivateKeyExportable,
			EnrollmentFlagNames:            tmpl.EnrollmentFlagNames,
			NameFlagNames:                  tmpl.NameFlagNames,
			Exploitability:                 tmpl.Exploitability,
			Vulnerabilities:                tmpl.Vulnerabilities,
		}

		// EKU names for human readability
		if len(tmpl.ExtendedKeyUsage) == 0 {
			jsonTmpl.ExtendedKeyUsage = []string{}
		}

		// Clean up empty slices for nice JSON
		if len(jsonTmpl.EnrollmentFlagNames) == 0 {
			jsonTmpl.EnrollmentFlagNames = nil
		}
		if len(jsonTmpl.NameFlagNames) == 0 {
			jsonTmpl.NameFlagNames = nil
		}

		// Strip empty exploitability
		jsonTmpl.Exploitability = strings.TrimSpace(jsonTmpl.Exploitability)

		// Include permissions if available
		if tmpl.Permissions != nil {
			jsonTmpl.Permissions = &JSONPermissions{
				Owner:             tmpl.Permissions.Owner,
				EnrollmentRights:  tmpl.Permissions.EnrollmentRights,
				FullControl:       tmpl.Permissions.FullControlPrincipals,
				WriteOwner:        tmpl.Permissions.WriteOwnerPrincipals,
				WriteDACL:         tmpl.Permissions.WriteDACLPrincipals,
				WriteProperty:     tmpl.Permissions.WritePropertyPrincipals,
				AllExtendedRights: tmpl.Permissions.AllExtendedRights,
			}
		}

		output.Templates = append(output.Templates, jsonTmpl)
	}

	var enc *json.Encoder
	enc = json.NewEncoder(f.Writer)
	if f.Indent {
		enc.SetIndent("", "  ")
	}

	return enc.Encode(output)
}
