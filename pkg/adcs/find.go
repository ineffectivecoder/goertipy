package adcs

import (
	goertipyldap "github.com/slacker/goertipy/pkg/ldap"
	"github.com/slacker/goertipy/pkg/security"
)

// FindOptions configures the find operation
type FindOptions struct {
	// Filtering
	VulnerableOnly bool
	EnabledOnly    bool
	HideAdmins     bool

	// Include OID enumeration
	EnumerateOIDs bool
}

// FindResult contains the results of a find operation
type FindResult struct {
	Domain    string
	CAs       []*CertificateAuthority
	Templates []*CertificateTemplate

	// Statistics
	TotalCAs            int
	TotalTemplates      int
	VulnerableTemplates int
}

// Find performs AD CS enumeration
func Find(client *goertipyldap.Client, opts FindOptions) (*FindResult, error) {
	result := &FindResult{
		Domain: client.Domain(),
	}

	// Create SID resolver for permission lookup
	sidResolver := goertipyldap.NewSIDResolver(client)

	// Enumerate CAs
	cas, err := EnumerateCAs(client)
	if err != nil {
		return nil, err
	}

	// Analyze CA permissions for ESC7 detection
	for _, ca := range cas {
		ca.AnalyzeCAPermissions(sidResolver.Resolve)
	}

	result.CAs = cas
	result.TotalCAs = len(cas)

	// Build a set of enabled templates (published by at least one CA)
	enabledTemplates := make(map[string]bool)
	for _, ca := range cas {
		for _, tmpl := range ca.CertificateTemplates {
			enabledTemplates[tmpl] = true
		}
	}

	// Enumerate templates
	templates, err := EnumerateTemplates(client)
	if err != nil {
		return nil, err
	}

	// Parse permissions for each template and check for ESC4
	for _, tmpl := range templates {
		// Set enabled status
		tmpl.Enabled = enabledTemplates[tmpl.Name]

		if len(tmpl.SecurityDescriptor) > 0 {
			perms, err := security.ParseTemplatePermissions(tmpl.SecurityDescriptor, sidResolver.Resolve)
			if err == nil {
				tmpl.Permissions = perms
				tmpl.EnrollmentRights = perms.EnrollmentRights

				// Check for ESC4 - dangerous permissions
				if perms.HasDangerousPermissions() {
					// Add ESC4 if not already present
					hasESC4 := false
					for _, v := range tmpl.Vulnerabilities {
						if v == "ESC4" {
							hasESC4 = true
							break
						}
					}
					if !hasESC4 {
						tmpl.Vulnerabilities = append(tmpl.Vulnerabilities, "ESC4")
					}
				}
			}
		}
	}

	// Filter templates based on options
	var filteredTemplates []*CertificateTemplate
	for _, tmpl := range templates {
		if opts.EnabledOnly && !tmpl.Enabled {
			continue
		}

		if opts.VulnerableOnly && !tmpl.IsVulnerable() {
			continue
		}

		filteredTemplates = append(filteredTemplates, tmpl)

		if tmpl.IsVulnerable() {
			result.VulnerableTemplates++
		}
	}

	result.Templates = filteredTemplates
	result.TotalTemplates = len(templates)

	return result, nil
}
