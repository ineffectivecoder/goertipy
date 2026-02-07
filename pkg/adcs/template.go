package adcs

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"

	"github.com/go-ldap/ldap/v3"
	"github.com/slacker/goertipy/pkg/adcs/flags"
	goertipyldap "github.com/slacker/goertipy/pkg/ldap"
	"github.com/slacker/goertipy/pkg/security"
)

// CertificateTemplate represents an AD CS certificate template
type CertificateTemplate struct {
	Name          string
	DisplayName   string
	DN            string
	OID           string
	SchemaVersion int

	// Flags (raw values)
	CertificateNameFlag uint32
	EnrollmentFlag      uint32
	PrivateKeyFlag      uint32

	// Extended Key Usage
	ExtendedKeyUsage    []string
	ApplicationPolicies []string

	// Enrollment requirements
	RASignature      int
	IssuancePolicies []string // msPKI-RA-Policies — OIDs required for issuance (ESC13)

	// Validity and renewal
	ValidityPeriod string
	RenewalPeriod  string

	// Security descriptor (raw)
	SecurityDescriptor []byte

	// Parsed permissions
	Permissions *security.TemplatePermissions

	// Computed properties
	EnrolleeSuppliesSubject        bool
	EnrolleeSuppliesSubjectAltName bool
	RequiresManagerApproval        bool
	HasAuthenticationEKU           bool
	HasClientAuthEKU               bool // Explicitly has Client Auth EKU
	NoSecurityExtension            bool
	PrivateKeyExportable           bool
	Enabled                        bool     // True if published by at least one CA
	PublishedBy                    []string // CA names that publish this template

	// Human-readable flag names
	EnrollmentFlagNames []string
	NameFlagNames       []string

	// Exploitability assessment
	Exploitability string // "Exploitable", "Conditional", "Requires Privileges"

	// Vulnerabilities detected
	Vulnerabilities []string

	// Enrollment rights (parsed from security descriptor)
	EnrollmentRights []string
}

// EnumerateTemplates discovers all certificate templates
func EnumerateTemplates(client *goertipyldap.Client) ([]*CertificateTemplate, error) {
	// Build base DN for certificate templates
	baseDN := fmt.Sprintf("CN=Certificate Templates,CN=Public Key Services,CN=Services,%s",
		client.ConfigurationNC())

	// Attributes to retrieve
	attributes := []string{
		"cn",
		"displayName",
		"distinguishedName",
		"msPKI-Cert-Template-OID",
		"msPKI-Template-Schema-Version",
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
	}

	entries, err := client.Search(
		baseDN,
		ldap.ScopeWholeSubtree,
		"(objectClass=pKICertificateTemplate)",
		attributes,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate templates: %w", err)
	}

	var templates []*CertificateTemplate
	for _, entry := range entries {
		tmpl := parseTemplateEntry(entry)
		// Analyze for vulnerabilities
		tmpl.analyzeVulnerabilities()
		templates = append(templates, tmpl)
	}

	return templates, nil
}

// parseTemplateEntry parses an LDAP entry into a CertificateTemplate
func parseTemplateEntry(entry *ldap.Entry) *CertificateTemplate {
	tmpl := &CertificateTemplate{
		Name:                entry.GetAttributeValue("cn"),
		DisplayName:         entry.GetAttributeValue("displayName"),
		DN:                  entry.GetAttributeValue("distinguishedName"),
		OID:                 entry.GetAttributeValue("msPKI-Cert-Template-OID"),
		ExtendedKeyUsage:    entry.GetAttributeValues("pKIExtendedKeyUsage"),
		ApplicationPolicies: entry.GetAttributeValues("msPKI-Certificate-Application-Policy"),
		IssuancePolicies:    entry.GetAttributeValues("msPKI-RA-Policies"),
		SecurityDescriptor:  entry.GetRawAttributeValue("nTSecurityDescriptor"),
	}

	// Parse integer attributes
	if v := entry.GetAttributeValue("msPKI-Template-Schema-Version"); v != "" {
		tmpl.SchemaVersion, _ = strconv.Atoi(v)
	}
	if v := entry.GetAttributeValue("msPKI-Certificate-Name-Flag"); v != "" {
		if i, err := strconv.ParseInt(v, 10, 64); err == nil {
			tmpl.CertificateNameFlag = uint32(i)
		}
	}
	if v := entry.GetAttributeValue("msPKI-Enrollment-Flag"); v != "" {
		if i, err := strconv.ParseInt(v, 10, 64); err == nil {
			tmpl.EnrollmentFlag = uint32(i)
		}
	}
	if v := entry.GetAttributeValue("msPKI-Private-Key-Flag"); v != "" {
		if i, err := strconv.ParseInt(v, 10, 64); err == nil {
			tmpl.PrivateKeyFlag = uint32(i)
		}
	}
	if v := entry.GetAttributeValue("msPKI-RA-Signature"); v != "" {
		tmpl.RASignature, _ = strconv.Atoi(v)
	}

	// Parse validity period
	if data := entry.GetRawAttributeValue("pKIExpirationPeriod"); len(data) > 0 {
		tmpl.ValidityPeriod = parseFiletimeDuration(data)
	}
	if data := entry.GetRawAttributeValue("pKIOverlapPeriod"); len(data) > 0 {
		tmpl.RenewalPeriod = parseFiletimeDuration(data)
	}

	// Compute boolean flags
	tmpl.EnrolleeSuppliesSubject = flags.HasFlag(tmpl.CertificateNameFlag, flags.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
	tmpl.EnrolleeSuppliesSubjectAltName = flags.HasFlag(tmpl.CertificateNameFlag, flags.CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME)
	tmpl.RequiresManagerApproval = flags.HasFlag(tmpl.EnrollmentFlag, flags.CT_FLAG_PEND_ALL_REQUESTS)
	tmpl.NoSecurityExtension = flags.HasFlag(tmpl.CertificateNameFlag, flags.CT_FLAG_NO_SECURITY_EXTENSION)
	tmpl.PrivateKeyExportable = flags.HasFlag(tmpl.PrivateKeyFlag, flags.CT_FLAG_EXPORTABLE_KEY)

	// Check for authentication EKU
	tmpl.HasAuthenticationEKU = tmpl.hasAuthEKU()
	tmpl.HasClientAuthEKU = tmpl.hasExplicitClientAuth()

	// Parse human-readable flag names
	tmpl.EnrollmentFlagNames = flags.GetSetFlags(tmpl.EnrollmentFlag, flags.EnrollmentFlagNames)
	sort.Strings(tmpl.EnrollmentFlagNames)
	tmpl.NameFlagNames = flags.GetSetFlags(tmpl.CertificateNameFlag, flags.NameFlagNames)
	sort.Strings(tmpl.NameFlagNames)

	return tmpl
}

// hasExplicitClientAuth checks for explicit Client Authentication EKU
func (t *CertificateTemplate) hasExplicitClientAuth() bool {
	for _, eku := range t.ExtendedKeyUsage {
		if eku == flags.EKU_CLIENT_AUTH {
			return true
		}
	}
	for _, policy := range t.ApplicationPolicies {
		if policy == flags.EKU_CLIENT_AUTH {
			return true
		}
	}
	return false
}

// hasAuthEKU checks if the template has an authentication-capable EKU
func (t *CertificateTemplate) hasAuthEKU() bool {
	// If no EKU is defined, it can be used for any purpose (including auth)
	if len(t.ExtendedKeyUsage) == 0 {
		return true
	}

	for _, eku := range t.ExtendedKeyUsage {
		if flags.IsAuthenticationEKU(eku) {
			return true
		}
	}

	// Also check application policies
	for _, policy := range t.ApplicationPolicies {
		if flags.IsAuthenticationEKU(policy) {
			return true
		}
	}

	return false
}

// analyzeVulnerabilities checks the template for ESC vulnerabilities
func (t *CertificateTemplate) analyzeVulnerabilities() {
	t.Vulnerabilities = nil

	// ESC1: Enrollee supplies subject + Auth EKU + no manager approval + no authorized signatures
	if t.EnrolleeSuppliesSubject && t.HasAuthenticationEKU && !t.RequiresManagerApproval && t.RASignature == 0 {
		t.Vulnerabilities = append(t.Vulnerabilities, "ESC1")
	}

	// ESC2: Any Purpose EKU or no EKU + no manager approval
	if t.hasAnyPurposeOrNoEKU() && !t.RequiresManagerApproval && t.RASignature == 0 {
		t.Vulnerabilities = append(t.Vulnerabilities, "ESC2")
	}

	// ESC3: Certificate Request Agent EKU
	if t.hasCertificateRequestAgentEKU() && !t.RequiresManagerApproval && t.RASignature == 0 {
		t.Vulnerabilities = append(t.Vulnerabilities, "ESC3")
	}

	// ESC9: No security extension + enrollee supplies subject
	if t.NoSecurityExtension && t.EnrolleeSuppliesSubject {
		t.Vulnerabilities = append(t.Vulnerabilities, "ESC9")
	}

	// ESC13: Template has issuance policies (msPKI-RA-Policies) linked to groups
	// When the OID is linked to a universal group via msDS-OIDToGroupLink,
	// any certificate issued adds the user to that group
	if len(t.IssuancePolicies) > 0 && t.HasAuthenticationEKU && !t.RequiresManagerApproval && t.RASignature == 0 {
		t.Vulnerabilities = append(t.Vulnerabilities, "ESC13")
	}

	// ESC15/EKUwu: V1 template + enrollee supplies subject
	if t.SchemaVersion == 1 && t.EnrolleeSuppliesSubject {
		t.Vulnerabilities = append(t.Vulnerabilities, "ESC15")
	}
}

// hasAnyPurposeOrNoEKU checks for Any Purpose EKU or no EKU defined
func (t *CertificateTemplate) hasAnyPurposeOrNoEKU() bool {
	if len(t.ExtendedKeyUsage) == 0 {
		return true
	}
	for _, eku := range t.ExtendedKeyUsage {
		if eku == flags.EKU_ANY_PURPOSE {
			return true
		}
	}
	return false
}

// hasCertificateRequestAgentEKU checks for Certificate Request Agent EKU
func (t *CertificateTemplate) hasCertificateRequestAgentEKU() bool {
	for _, eku := range t.ExtendedKeyUsage {
		if eku == flags.EKU_CERTIFICATE_REQUEST_AGENT {
			return true
		}
	}
	return false
}

// GetEKUNames returns human-readable EKU names
func (t *CertificateTemplate) GetEKUNames() []string {
	if len(t.ExtendedKeyUsage) == 0 {
		return []string{"(No EKUs - Any Purpose)"}
	}

	var names []string
	for _, eku := range t.ExtendedKeyUsage {
		if name, ok := flags.EKUNames[eku]; ok {
			names = append(names, name)
		} else {
			names = append(names, eku)
		}
	}
	return names
}

// parseFiletimeDuration converts a Windows FILETIME duration to human-readable format
func parseFiletimeDuration(data []byte) string {
	if len(data) < 8 {
		return ""
	}

	// FILETIME is in 100-nanosecond intervals (negative for duration)
	val := int64(binary.LittleEndian.Uint64(data))
	if val >= 0 {
		return ""
	}

	// Convert to positive and to seconds
	seconds := (-val) / 10000000

	// Convert to days/weeks/years
	days := seconds / 86400
	if days >= 365 {
		years := days / 365
		return fmt.Sprintf("%d years", years)
	} else if days >= 7 {
		weeks := days / 7
		return fmt.Sprintf("%d weeks", weeks)
	}
	return fmt.Sprintf("%d days", days)
}

// IsVulnerable returns true if any vulnerabilities were detected
func (t *CertificateTemplate) IsVulnerable() bool {
	return len(t.Vulnerabilities) > 0
}
