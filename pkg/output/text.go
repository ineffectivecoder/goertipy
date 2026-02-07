package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/slacker/goertipy/pkg/adcs"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[91m"
	colorGreen  = "\033[92m"
	colorYellow = "\033[93m"
	colorCyan   = "\033[96m"
	colorBold   = "\033[1m"
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

		// Schema version
		f.printf("    Schema Version: %d\n", tmpl.SchemaVersion)

		// Validity
		if tmpl.ValidityPeriod != "" {
			f.printf("    Validity: %s\n", tmpl.ValidityPeriod)
		}

		// EKUs
		ekus := tmpl.GetEKUNames()
		f.printf("    Extended Key Usage: %s\n", strings.Join(ekus, ", "))

		// Key flags
		if tmpl.EnrolleeSuppliesSubject {
			f.printf("    %s Enrollee Supplies Subject: Yes\n", f.yellow("[*]"))
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

		// Vulnerabilities
		if len(tmpl.Vulnerabilities) > 0 {
			f.printf("    %s %s\n",
				f.red("[!] VULNERABLE:"),
				f.red(strings.Join(tmpl.Vulnerabilities, ", ")))
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
