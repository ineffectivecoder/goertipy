package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/slacker/goertipy/pkg/adcs"
)

// ANSI color codes
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[91m"
	colorGreen   = "\033[92m"
	colorYellow  = "\033[93m"
	colorCyan    = "\033[96m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
	colorMagenta = "\033[95m"
)

// TextFormatter outputs results in human-readable text format
type TextFormatter struct {
	Writer io.Writer
	Color  bool
}

// NewTextFormatter creates a new text formatter
func NewTextFormatter(w io.Writer, color bool) *TextFormatter {
	return &TextFormatter{Writer: w, Color: color}
}

// Format outputs the find results as text
func (f *TextFormatter) Format(result *adcs.FindResult) error {
	// Header
	f.println(f.bold("=" + strings.Repeat("=", 79)))
	f.println(f.bold("Goertipy - AD CS Enumeration"))
	f.println(f.bold("=" + strings.Repeat("=", 79)))
	f.println("")

	// Domain info
	if result.Domain != "" {
		f.printf("Domain: %s\n", f.cyan(result.Domain))
		f.println("")
	}

	// Certificate Authorities
	f.println(f.bold("-" + strings.Repeat("-", 79)))
	f.printf("%s (%d found)\n", f.bold("Certificate Authorities"), len(result.CAs))
	f.println(f.bold("-" + strings.Repeat("-", 79)))

	for _, ca := range result.CAs {
		f.println("")
		f.printf("  CA Name: %s\n", f.bold(ca.CAName))
		f.printf("    DNS Name: %s\n", ca.DNSHostName)
		f.printf("    Templates: %d\n", len(ca.CertificateTemplates))

		// Show CA cert validity
		if ca.Certificate != nil {
			if ca.IsExpired() {
				f.printf("    %s Certificate EXPIRED: %s - %s\n",
					f.red("[!]"), ca.NotBefore.Format("2006-01-02"), ca.NotAfter.Format("2006-01-02"))
			} else {
				f.printf("    Validity: %s - %s\n",
					ca.NotBefore.Format("2006-01-02"), ca.NotAfter.Format("2006-01-02"))
			}
		}

		// Web enrollment
		if ca.HasWebEnrollment {
			f.printf("    %s Web Enrollment: Enabled\n", f.yellow("[*]"))
		}

		// Enrollment endpoints
		if len(ca.EnrollmentEndpoints) > 0 {
			f.println("    Enrollment Endpoints:")
			for _, ep := range ca.EnrollmentEndpoints {
				f.printf("      - %s\n", f.yellow(ep))
			}
		}

		// CA Permissions (ManageCA / ManageCertificates)
		if len(ca.ManageCAPrincipals) > 0 {
			f.println("    ManageCA:")
			for _, p := range ca.ManageCAPrincipals {
				f.printf("      - %s\n", p)
			}
		}
		if len(ca.ManageCertificatesPrincipals) > 0 {
			f.println("    ManageCertificates:")
			for _, p := range ca.ManageCertificatesPrincipals {
				f.printf("      - %s\n", p)
			}
		}

		if len(ca.Vulnerabilities) > 0 {
			f.printf("    %s %s\n",
				f.red("[!] VULNERABLE:"),
				f.red(strings.Join(ca.Vulnerabilities, ", ")))
		}
	}

	// Certificate Templates
	f.println("")
	f.println(f.bold("-" + strings.Repeat("-", 79)))
	f.printf("%s (%d shown / %d total)\n",
		f.bold("Certificate Templates"), len(result.Templates), result.TotalTemplates)
	f.println(f.bold("-" + strings.Repeat("-", 79)))

	for _, tmpl := range result.Templates {
		f.println("")

		// Template name with enabled status
		enabledStr := f.red("Disabled")
		if tmpl.Enabled {
			enabledStr = f.green("Enabled")
		}
		f.printf("  Template: %s [%s]\n", f.bold(tmpl.Name), enabledStr)

		if tmpl.DisplayName != "" && tmpl.DisplayName != tmpl.Name {
			f.printf("    Display Name: %s\n", tmpl.DisplayName)
		}

		// Published by CAs
		if len(tmpl.PublishedBy) > 0 {
			f.printf("    Published By: %s\n", f.dim(strings.Join(tmpl.PublishedBy, ", ")))
		}

		// Schema version
		f.printf("    Schema Version: %d\n", tmpl.SchemaVersion)

		// Validity
		if tmpl.ValidityPeriod != "" {
			f.printf("    Validity: %s\n", tmpl.ValidityPeriod)
		}

		// EKUs with Client Auth highlight
		ekus := tmpl.GetEKUNames()
		ekuStr := strings.Join(ekus, ", ")
		if tmpl.HasClientAuthEKU {
			ekuStr = f.yellow(ekuStr)
		}
		f.printf("    Extended Key Usage: %s\n", ekuStr)

		// Key flags
		if tmpl.EnrolleeSuppliesSubject {
			f.printf("    %s Enrollee Supplies Subject: %s\n", f.yellow("[*]"), "ENROLLEE_SUPPLIES_SUBJECT")
		}
		if tmpl.EnrolleeSuppliesSubjectAltName {
			f.printf("    %s Enrollee Supplies SAN: %s\n", f.yellow("[*]"), "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME")
		}
		if tmpl.RequiresManagerApproval {
			f.printf("    %s Requires Manager Approval: Yes\n", f.yellow("[*]"))
		}
		if tmpl.RASignature > 0 {
			f.printf("    %s Authorized Signatures Required: %d\n", f.yellow("[*]"), tmpl.RASignature)
		}
		if tmpl.NoSecurityExtension {
			f.printf("    %s No Security Extension: Yes\n", f.yellow("[*]"))
		}

		// Private key exportable
		if tmpl.PrivateKeyExportable {
			f.printf("    Private Key Exportable: %s\n", f.green("Yes"))
		} else {
			f.printf("    Private Key Exportable: No\n")
		}

		// Enrollment flags
		if len(tmpl.EnrollmentFlagNames) > 0 {
			f.printf("    Enrollment Flags: %s\n", f.dim(strings.Join(tmpl.EnrollmentFlagNames, ", ")))
		}

		// Certificate Name Flags
		if len(tmpl.NameFlagNames) > 0 {
			f.printf("    Name Flags: %s\n", f.dim(strings.Join(tmpl.NameFlagNames, ", ")))
		}

		if len(tmpl.IssuancePolicies) > 0 {
			f.printf("    %s Issuance Policies: %s\n", f.yellow("[*]"),
				strings.Join(tmpl.IssuancePolicies, ", "))
		}

		// Permissions
		if tmpl.Permissions != nil {
			f.println("    Permissions:")

			// Owner
			if tmpl.Permissions.Owner != "" {
				f.printf("      Owner: %s\n", tmpl.Permissions.Owner)
			}

			// Enrollment Rights
			if len(tmpl.Permissions.EnrollmentRights) > 0 {
				f.println("      Enrollment Rights:")
				for _, p := range tmpl.Permissions.EnrollmentRights {
					f.printf("        - %s\n", p)
				}
			}

			// Object Control Permissions
			if len(tmpl.Permissions.FullControlPrincipals) > 0 {
				f.println("      Full Control:")
				for _, p := range tmpl.Permissions.FullControlPrincipals {
					f.printf("        - %s\n", p)
				}
			}
			if len(tmpl.Permissions.WriteOwnerPrincipals) > 0 {
				f.println("      Write Owner:")
				for _, p := range tmpl.Permissions.WriteOwnerPrincipals {
					f.printf("        - %s\n", p)
				}
			}
			if len(tmpl.Permissions.WriteDACLPrincipals) > 0 {
				f.println("      Write DACL:")
				for _, p := range tmpl.Permissions.WriteDACLPrincipals {
					f.printf("        - %s\n", p)
				}
			}
			if len(tmpl.Permissions.WritePropertyPrincipals) > 0 {
				f.println("      Write Property:")
				for _, p := range tmpl.Permissions.WritePropertyPrincipals {
					f.printf("        - %s\n", p)
				}
			}
		}

		// Vulnerabilities with color-coded severity
		if len(tmpl.Vulnerabilities) > 0 {
			vulnStr := strings.Join(tmpl.Vulnerabilities, ", ")
			switch tmpl.Exploitability {
			case "Exploitable":
				f.printf("    %s %s %s\n",
					f.red("[!] VULNERABLE:"),
					f.red(vulnStr),
					f.red("[EXPLOITABLE]"))
			case "Conditional":
				f.printf("    %s %s %s\n",
					f.yellow("[!] VULNERABLE:"),
					f.yellow(vulnStr),
					f.yellow("[CONDITIONAL]"))
			case "Requires Privileges":
				f.printf("    %s %s %s\n",
					f.magenta("[!] VULNERABLE:"),
					f.magenta(vulnStr),
					f.magenta("[REQUIRES PRIVILEGES]"))
			default:
				f.printf("    %s %s\n",
					f.red("[!] VULNERABLE:"),
					f.red(vulnStr))
			}
		}
	}

	// Summary
	f.println("")
	f.println(f.bold("=" + strings.Repeat("=", 79)))
	f.println(f.bold("Summary"))
	f.println(f.bold("=" + strings.Repeat("=", 79)))
	f.printf("  Certificate Authorities: %d\n", result.TotalCAs)
	f.printf("  Certificate Templates: %d\n", result.TotalTemplates)

	if result.VulnerableTemplates > 0 {
		f.printf("  Vulnerable Templates: %s\n", f.red(fmt.Sprintf("%d", result.VulnerableTemplates)))

		// Exploitability breakdown
		if result.ExploitableTemplates > 0 {
			f.printf("    Directly Exploitable: %s\n", f.red(fmt.Sprintf("%d", result.ExploitableTemplates)))
		}
		if result.ConditionalTemplates > 0 {
			f.printf("    Conditional:          %s\n", f.yellow(fmt.Sprintf("%d", result.ConditionalTemplates)))
		}

		// ESC summary
		if len(result.ExploitableESCs) > 0 {
			f.printf("  ESCs Found: %s\n", f.red(strings.Join(result.ExploitableESCs, ", ")))
		}
	} else {
		f.printf("  Vulnerable Templates: %s\n", f.green("0"))
	}
	f.println("")

	return nil
}

func (f *TextFormatter) println(s string) {
	fmt.Fprintln(f.Writer, s)
}

func (f *TextFormatter) printf(format string, args ...interface{}) {
	fmt.Fprintf(f.Writer, format, args...)
}

// Color helpers — return plain text if color is disabled
func (f *TextFormatter) red(s string) string {
	if !f.Color {
		return s
	}
	return colorRed + s + colorReset
}

func (f *TextFormatter) green(s string) string {
	if !f.Color {
		return s
	}
	return colorGreen + s + colorReset
}

func (f *TextFormatter) yellow(s string) string {
	if !f.Color {
		return s
	}
	return colorYellow + s + colorReset
}

func (f *TextFormatter) cyan(s string) string {
	if !f.Color {
		return s
	}
	return colorCyan + s + colorReset
}

func (f *TextFormatter) bold(s string) string {
	if !f.Color {
		return s
	}
	return colorBold + s + colorReset
}

func (f *TextFormatter) dim(s string) string {
	if !f.Color {
		return s
	}
	return colorDim + s + colorReset
}

func (f *TextFormatter) magenta(s string) string {
	if !f.Color {
		return s
	}
	return colorMagenta + s + colorReset
}
