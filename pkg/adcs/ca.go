package adcs

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/slacker/goertipy/pkg/adcs/flags"
	goertipyldap "github.com/slacker/goertipy/pkg/ldap"
	"github.com/slacker/goertipy/pkg/security"
)

// CertificateAuthority represents an Enterprise CA
type CertificateAuthority struct {
	Name                 string
	DNSHostName          string
	DN                   string
	CertificateTemplates []string

	// Parsed CA certificate using x509 standard library
	Certificate    *x509.Certificate
	CertificateRaw []byte

	// Parsed from CA configuration
	CAName string

	// Certificate details (from x509)
	Subject      string
	Issuer       string
	SerialNumber string
	NotBefore    time.Time
	NotAfter     time.Time

	// ESC6: CA configuration flags
	// Contains EDITF_ATTRIBUTESUBJECTALTNAME2 if SAN override enabled
	CAFlags uint32

	// ESC7: CA security descriptor and parsed permissions
	SecurityDescriptor []byte
	Permissions        *security.TemplatePermissions

	// ESC8: HTTP enrollment servers
	EnrollmentServers []string
	HasWebEnrollment  bool

	// Vulnerabilities detected
	Vulnerabilities []string
}

// EnumerateCAs discovers all Enterprise CAs in the domain
func EnumerateCAs(client *goertipyldap.Client) ([]*CertificateAuthority, error) {
	// Build the base DN for enrollment services
	baseDN := fmt.Sprintf("CN=Enrollment Services,CN=Public Key Services,CN=Services,%s",
		client.ConfigurationNC())

	// Search for pKIEnrollmentService objects
	entries, err := client.Search(
		baseDN,
		ldap.ScopeWholeSubtree,
		"(objectClass=pKIEnrollmentService)",
		[]string{
			"cn",
			"dNSHostName",
			"distinguishedName",
			"certificateTemplates",
			"cACertificate",
			"flags",
			"nTSecurityDescriptor",
			"msPKI-Enrollment-Servers",
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate CAs: %w", err)
	}

	var cas []*CertificateAuthority
	for _, entry := range entries {
		ca := &CertificateAuthority{
			Name:                 entry.GetAttributeValue("cn"),
			DNSHostName:          entry.GetAttributeValue("dNSHostName"),
			DN:                   entry.GetAttributeValue("distinguishedName"),
			CertificateTemplates: entry.GetAttributeValues("certificateTemplates"),
			SecurityDescriptor:   entry.GetRawAttributeValue("nTSecurityDescriptor"),
			EnrollmentServers:    entry.GetAttributeValues("msPKI-Enrollment-Servers"),
		}

		// Parse CA certificate using x509 standard library
		if certData := entry.GetRawAttributeValue("cACertificate"); len(certData) > 0 {
			ca.CertificateRaw = certData
			if cert, err := x509.ParseCertificate(certData); err == nil {
				ca.Certificate = cert
				ca.Subject = cert.Subject.String()
				ca.Issuer = cert.Issuer.String()
				ca.SerialNumber = cert.SerialNumber.String()
				ca.NotBefore = cert.NotBefore
				ca.NotAfter = cert.NotAfter
			}
		}

		// Build CA name (hostname\name format)
		if ca.DNSHostName != "" {
			hostname := strings.Split(ca.DNSHostName, ".")[0]
			ca.CAName = fmt.Sprintf("%s\\%s", hostname, ca.Name)
		} else {
			ca.CAName = ca.Name
		}

		// Parse flags for ESC6 detection
		if flagStr := entry.GetAttributeValue("flags"); flagStr != "" {
			var f int64
			if _, err := fmt.Sscanf(flagStr, "%d", &f); err == nil {
				ca.CAFlags = uint32(f)
			}
		}

		// Check for web enrollment (ESC8)
		ca.HasWebEnrollment = len(ca.EnrollmentServers) > 0

		// Analyze CA-level vulnerabilities
		ca.analyzeCAVulnerabilities()

		cas = append(cas, ca)
	}

	return cas, nil
}

// analyzeCAVulnerabilities checks the CA for ESC6 and ESC8 vulnerabilities
func (ca *CertificateAuthority) analyzeCAVulnerabilities() {
	ca.Vulnerabilities = nil

	// ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 is set — allows any user to specify SAN
	if flags.HasFlag(ca.CAFlags, flags.EDITF_ATTRIBUTESUBJECTALTNAME2) {
		ca.Vulnerabilities = append(ca.Vulnerabilities, "ESC6")
	}

	// ESC8: HTTP-based enrollment is enabled (Web Enrollment / CEP / CES)
	if ca.HasWebEnrollment {
		ca.Vulnerabilities = append(ca.Vulnerabilities, "ESC8")
	}
}

// AnalyzeCAPermissions parses the CA security descriptor and checks for ESC7
func (ca *CertificateAuthority) AnalyzeCAPermissions(sidResolver func(string) string) {
	if len(ca.SecurityDescriptor) == 0 {
		return
	}

	perms, err := security.ParseTemplatePermissions(ca.SecurityDescriptor, sidResolver)
	if err != nil {
		return
	}
	ca.Permissions = perms

	// ESC7: Low-privilege users have ManageCA or ManageCertificates rights
	// This is detected via WriteDACL / WriteOwner / FullControl on the CA object
	// which grants effective ManageCA rights
	if perms.HasDangerousPermissions() {
		hasESC7 := false
		for _, v := range ca.Vulnerabilities {
			if v == "ESC7" {
				hasESC7 = true
				break
			}
		}
		if !hasESC7 {
			ca.Vulnerabilities = append(ca.Vulnerabilities, "ESC7")
		}
	}
}

// HasTemplate checks if the CA publishes a specific template
func (ca *CertificateAuthority) HasTemplate(templateName string) bool {
	for _, t := range ca.CertificateTemplates {
		if strings.EqualFold(t, templateName) {
			return true
		}
	}
	return false
}

// IsExpired returns true if the CA certificate is expired
func (ca *CertificateAuthority) IsExpired() bool {
	if ca.Certificate == nil {
		return false
	}
	return time.Now().After(ca.NotAfter)
}

// IsNotYetValid returns true if the CA certificate is not yet valid
func (ca *CertificateAuthority) IsNotYetValid() bool {
	if ca.Certificate == nil {
		return false
	}
	return time.Now().Before(ca.NotBefore)
}
