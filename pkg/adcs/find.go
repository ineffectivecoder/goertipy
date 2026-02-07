package adcs

import (
	"strings"

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

	// Filter by CA name
	CAName string
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

	// Exploitability breakdown
	ExploitableTemplates int
	ConditionalTemplates int

	// Top-level exploitable ESC list (deduplicated)
	ExploitableESCs []string
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

	// Filter CAs by name if specified
	if opts.CAName != "" {
		var filtered []*CertificateAuthority
		for _, ca := range cas {
			if strings.EqualFold(ca.Name, opts.CAName) || strings.EqualFold(ca.CAName, opts.CAName) {
				filtered = append(filtered, ca)
			}
		}
		cas = filtered
	}

	result.CAs = cas
	result.TotalCAs = len(cas)

	// Build a set of enabled templates (published by at least one CA)
	// and track which CAs publish each template
	enabledTemplates := make(map[string]bool)
	templateToCA := make(map[string][]string)
	for _, ca := range cas {
		for _, tmpl := range ca.CertificateTemplates {
			enabledTemplates[tmpl] = true
			templateToCA[tmpl] = append(templateToCA[tmpl], ca.CAName)
		}
	}

	// Enumerate templates
	templates, err := EnumerateTemplates(client)
	if err != nil {
		return nil, err
	}

	// Parse permissions for each template and check for ESC4
	escSeen := make(map[string]bool)
	for _, tmpl := range templates {
		// Set enabled status and publishing CAs
		tmpl.Enabled = enabledTemplates[tmpl.Name]
		tmpl.PublishedBy = templateToCA[tmpl.Name]

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

		// Compute exploitability
		tmpl.Exploitability = computeExploitability(tmpl)
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
			for _, v := range tmpl.Vulnerabilities {
				if !escSeen[v] {
					escSeen[v] = true
					result.ExploitableESCs = append(result.ExploitableESCs, v)
				}
			}
		}

		switch tmpl.Exploitability {
		case "Exploitable":
			result.ExploitableTemplates++
		case "Conditional":
			result.ConditionalTemplates++
		}
	}

	result.Templates = filteredTemplates
	result.TotalTemplates = len(templates)

	return result, nil
}

// computeExploitability determines how easily a vulnerability can be exploited
func computeExploitability(tmpl *CertificateTemplate) string {
	if len(tmpl.Vulnerabilities) == 0 {
		return ""
	}

	// If manager approval is required or authorized signatures needed, it's conditional
	if tmpl.RequiresManagerApproval || tmpl.RASignature > 0 {
		return "Conditional"
	}

	// If the template is not enabled, it's conditional
	if !tmpl.Enabled {
		return "Conditional"
	}

	// ESC4 (dangerous ACLs) requires additional exploitation steps
	for _, v := range tmpl.Vulnerabilities {
		if v == "ESC4" && len(tmpl.Vulnerabilities) == 1 {
			return "Requires Privileges"
		}
	}

	return "Exploitable"
}
