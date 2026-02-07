package commands

import (
	"fmt"
	"os"
	"strings"

	"github.com/slacker/goertipy/pkg/adcs"
	goertipyldap "github.com/slacker/goertipy/pkg/ldap"
	goertipylog "github.com/slacker/goertipy/pkg/log"
	"github.com/slacker/goertipy/pkg/output"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// FindFlags holds the flags for the find command
type FindFlags struct {
	// Authentication
	Username string
	Password string
	Hashes   string

	// Target
	Domain string
	DCIP   string
	Scheme string

	// Output
	OutputFile   string
	OutputJSON   bool
	OutputText   bool
	OutputStdout bool
	NoColor      bool

	// Report generation
	Report     bool
	ReportHTML bool
	ReportPDF  bool

	// Filtering
	VulnerableOnly bool
	EnabledOnly    bool
	HideAdmins     bool
	CAName         string

	// Verbosity
	Debug   bool
	Verbose bool

	// Proxy
	Proxy string
}

var findFlags FindFlags

// NewFindCommand creates the find command
func NewFindCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "find",
		Short: "Enumerate AD CS Certificate Authorities and Templates",
		Long: `Enumerate Active Directory Certificate Services (AD CS) configuration.

This command discovers Certificate Authorities, certificate templates, and
identifies potential vulnerabilities (ESC1-ESC16).`,
		RunE: runFind,
	}

	// Authentication flags
	cmd.Flags().StringVarP(&findFlags.Username, "username", "u", "", "Username (user@domain or DOMAIN\\user)")
	cmd.Flags().StringVarP(&findFlags.Password, "password", "p", "", "Password")
	cmd.Flags().StringVarP(&findFlags.Hashes, "hashes", "H", "", "NTLM hash (LM:NT or :NT)")

	// Target flags
	cmd.Flags().StringVarP(&findFlags.Domain, "domain", "d", "", "Target domain")
	cmd.Flags().StringVar(&findFlags.DCIP, "dc-ip", "", "Domain Controller IP address")
	cmd.Flags().StringVar(&findFlags.Scheme, "scheme", "ldaps", "LDAP scheme (ldap or ldaps)")

	// Output flags
	cmd.Flags().StringVarP(&findFlags.OutputFile, "output", "o", "", "Output file prefix")
	cmd.Flags().BoolVar(&findFlags.OutputJSON, "json", false, "Output JSON format")
	cmd.Flags().BoolVar(&findFlags.OutputText, "text", true, "Output text format")
	cmd.Flags().BoolVar(&findFlags.OutputStdout, "stdout", false, "Output to stdout only")
	cmd.Flags().BoolVar(&findFlags.NoColor, "no-color", false, "Disable colored output")

	// Report generation
	cmd.Flags().BoolVar(&findFlags.Report, "report", false, "Generate Markdown pentest report")
	cmd.Flags().BoolVar(&findFlags.ReportHTML, "report-html", false, "Generate HTML pentest report")
	cmd.Flags().BoolVar(&findFlags.ReportPDF, "report-pdf", false, "Generate PDF pentest report (requires wkhtmltopdf or Chrome)")

	// Filtering flags
	cmd.Flags().BoolVar(&findFlags.VulnerableOnly, "vulnerable", false, "Only show vulnerable templates")
	cmd.Flags().BoolVar(&findFlags.EnabledOnly, "enabled", false, "Only show enabled templates")
	cmd.Flags().BoolVar(&findFlags.HideAdmins, "hide-admins", false, "Hide default admin permissions")
	cmd.Flags().StringVar(&findFlags.CAName, "ca-name", "", "Filter templates by publishing CA name")

	// Verbosity
	cmd.Flags().BoolVar(&findFlags.Debug, "debug", false, "Enable debug output")
	cmd.Flags().BoolVarP(&findFlags.Verbose, "verbose", "v", false, "Enable verbose output")

	// Proxy
	cmd.Flags().StringVar(&findFlags.Proxy, "proxy", "", "SOCKS5 proxy URL (e.g., socks5://127.0.0.1:1080)")

	return cmd
}

func runFind(cmd *cobra.Command, args []string) error {
	// Configure logger
	log := goertipylog.New(goertipylog.LevelError, os.Stderr)
	if findFlags.Verbose {
		log.SetLevel(goertipylog.LevelInfo)
	}
	if findFlags.Debug {
		log.SetLevel(goertipylog.LevelDebug)
	}

	// Validate required flags
	if findFlags.Username == "" {
		return fmt.Errorf("username is required (-u/--username)")
	}
	if findFlags.DCIP == "" {
		return fmt.Errorf("DC IP is required (--dc-ip)")
	}

	// Prompt for password if not provided
	if findFlags.Password == "" && findFlags.Hashes == "" {
		fmt.Print("Password: ")
		passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println() // Print newline after password input
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		findFlags.Password = string(passwordBytes)
	}

	// Parse hash if provided
	var ntHash string
	if findFlags.Hashes != "" {
		_, nt, err := goertipyldap.ParseHashes(findFlags.Hashes)
		if err != nil {
			return fmt.Errorf("invalid hashes: %w", err)
		}
		ntHash = nt
		log.Info("Using NTLM hash authentication")
	}

	// Determine port based on scheme
	port := 636
	useTLS := true
	if findFlags.Scheme == "ldap" {
		port = 389
		useTLS = false
	}

	// Connect to LDAP
	log.Info("Connecting to %s:%d (TLS: %v)", findFlags.DCIP, port, useTLS)

	client, err := goertipyldap.Connect(goertipyldap.Options{
		Server:             findFlags.DCIP,
		Port:               port,
		UseTLS:             useTLS,
		Username:           findFlags.Username,
		Password:           findFlags.Password,
		NTHash:             ntHash,
		Domain:             findFlags.Domain,
		InsecureSkipVerify: true, // For lab environments
		ProxyURL:           findFlags.Proxy,
	})
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer client.Close()

	log.Info("Connected successfully")
	log.Debug("Base DN: %s", client.BaseDN())
	log.Debug("Configuration NC: %s", client.ConfigurationNC())

	// Run find
	log.Info("Enumerating AD CS...")

	result, err := adcs.Find(client, adcs.FindOptions{
		VulnerableOnly: findFlags.VulnerableOnly,
		EnabledOnly:    findFlags.EnabledOnly,
		HideAdmins:     findFlags.HideAdmins,
		CAName:         findFlags.CAName,
	})
	if err != nil {
		return fmt.Errorf("enumeration failed: %w", err)
	}

	log.Info("Found %d CAs, %d templates (%d vulnerable)",
		result.TotalCAs, result.TotalTemplates, result.VulnerableTemplates)

	// Output results
	if findFlags.OutputJSON {
		formatter := output.NewJSONFormatter(os.Stdout, true)
		if err := formatter.Format(result); err != nil {
			return fmt.Errorf("failed to format JSON output: %w", err)
		}
	} else {
		formatter := output.NewTextFormatter(os.Stdout, !findFlags.NoColor)
		if err := formatter.Format(result); err != nil {
			return fmt.Errorf("failed to format text output: %w", err)
		}
	}

	// Generate reports if requested
	if findFlags.Report || findFlags.ReportHTML || findFlags.ReportPDF {
		domainName := result.Domain
		if findFlags.Domain != "" {
			domainName = findFlags.Domain
		}
		if domainName == "" {
			domainName = client.Domain()
		}
		// Parse domain from username (user@domain) as last resort
		if domainName == "" {
			if parts := strings.SplitN(findFlags.Username, "@", 2); len(parts) == 2 {
				domainName = parts[1]
			}
		}
		// Clean domain for filename
		safeDomain := strings.ReplaceAll(domainName, ".", "_")

		if findFlags.Report {
			mdPath := safeDomain + "_report.md"
			mdFile, err := os.Create(mdPath)
			if err != nil {
				return fmt.Errorf("failed to create report file: %w", err)
			}
			defer mdFile.Close()

			formatter := output.NewReportFormatter(mdFile, domainName, findFlags.DCIP, false)
			if err := formatter.Format(result); err != nil {
				return fmt.Errorf("failed to generate Markdown report: %w", err)
			}
			fmt.Fprintf(os.Stderr, "[+] Markdown report saved: %s\n", mdPath)
		}

		if findFlags.ReportHTML {
			htmlPath := safeDomain + "_report.html"
			htmlFile, err := os.Create(htmlPath)
			if err != nil {
				return fmt.Errorf("failed to create HTML report file: %w", err)
			}
			defer htmlFile.Close()

			formatter := output.NewReportFormatter(htmlFile, domainName, findFlags.DCIP, true)
			if err := formatter.Format(result); err != nil {
				return fmt.Errorf("failed to generate HTML report: %w", err)
			}
			fmt.Fprintf(os.Stderr, "[+] HTML report saved: %s\n", htmlPath)
		}

		if findFlags.ReportPDF {
			pdfPath := safeDomain + "_report.pdf"
			if err := output.GeneratePDF(result, domainName, findFlags.DCIP, pdfPath); err != nil {
				return fmt.Errorf("failed to generate PDF report: %w", err)
			}
			fmt.Fprintf(os.Stderr, "[+] PDF report saved: %s\n", pdfPath)
		}
	}

	return nil
}
