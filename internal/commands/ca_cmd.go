package commands

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/go-ldap/ldap/v3"
	goertipyldap "github.com/slacker/goertipy/pkg/ldap"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type CAFlags struct {
	CA       string
	Username string
	Password string
	Hashes   string
	Domain   string
	DCIP     string
	Scheme   string
	Output   string
	Debug    bool
}

var caFlags CAFlags

// NewCACommand creates the ca subcommand.
func NewCACommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "CA management operations",
		Long:  `Manage Certificate Authority — backup CA certificate, inspect configuration.`,
	}

	backupCmd := &cobra.Command{
		Use:   "backup",
		Short: "Backup CA certificate from LDAP",
		Long:  `Fetches the CA certificate from Active Directory (published in CN=Enrollment Services) and saves it as a PEM file.`,
		RunE:  runCABackup,
	}

	backupCmd.Flags().StringVar(&caFlags.CA, "ca", "", "CA name (e.g., corp-CA)")
	backupCmd.Flags().StringVarP(&caFlags.Username, "username", "u", "", "Username")
	backupCmd.Flags().StringVarP(&caFlags.Password, "password", "p", "", "Password")
	backupCmd.Flags().StringVarP(&caFlags.Hashes, "hashes", "H", "", "NTLM hash (LM:NT or :NT)")
	backupCmd.Flags().StringVarP(&caFlags.Domain, "domain", "d", "", "Target domain")
	backupCmd.Flags().StringVar(&caFlags.DCIP, "dc-ip", "", "Domain Controller IP")
	backupCmd.Flags().StringVar(&caFlags.Scheme, "scheme", "ldaps", "LDAP scheme: ldap or ldaps")
	backupCmd.Flags().StringVarP(&caFlags.Output, "output", "o", "", "Output file (default: <ca-name>_CA.pem)")
	backupCmd.Flags().BoolVar(&caFlags.Debug, "debug", false, "Debug output")

	cmd.AddCommand(backupCmd)
	return cmd
}

func runCABackup(cmd *cobra.Command, args []string) error {
	if caFlags.Username == "" {
		return fmt.Errorf("username is required (-u)")
	}
	if caFlags.DCIP == "" {
		return fmt.Errorf("DC IP is required (--dc-ip)")
	}

	// Extract domain from username if not specified
	domain := caFlags.Domain
	username := caFlags.Username
	if domain == "" {
		if strings.Contains(username, "@") {
			parts := strings.SplitN(username, "@", 2)
			domain = parts[1]
			username = parts[0]
		} else {
			return fmt.Errorf("domain is required (-d) or use user@domain format")
		}
	}

	// Parse hashes
	_, ntHash, err := goertipyldap.ParseHashes(caFlags.Hashes)
	if err != nil {
		return fmt.Errorf("invalid hash format: %w", err)
	}

	// Prompt for password if needed
	password := caFlags.Password
	if password == "" && ntHash == "" {
		fmt.Print("Password: ")
		passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		fmt.Println()
		password = string(passwordBytes)
	}

	// Connect LDAP
	port := 636
	useTLS := true
	if caFlags.Scheme == "ldap" {
		port = 389
		useTLS = false
	}

	fmt.Printf("[*] Connecting to %s via %s\n", caFlags.DCIP, strings.ToUpper(caFlags.Scheme))

	client, err := goertipyldap.Connect(goertipyldap.Options{
		Server:             caFlags.DCIP,
		Port:               port,
		UseTLS:             useTLS,
		Username:           username,
		Password:           password,
		Domain:             domain,
		NTHash:             ntHash,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return fmt.Errorf("LDAP connection failed: %w", err)
	}
	defer client.Close()

	configNC := client.ConfigurationNC()
	fmt.Printf("[*] Configuration NC: %s\n", configNC)

	// Search for CA in Enrollment Services
	enrollServicesBase := fmt.Sprintf("CN=Enrollment Services,CN=Public Key Services,CN=Services,%s", configNC)

	filter := "(objectClass=pKIEnrollmentService)"
	if caFlags.CA != "" {
		filter = fmt.Sprintf("(&(objectClass=pKIEnrollmentService)(cn=%s))", ldap.EscapeFilter(caFlags.CA))
	}

	entries, err := client.Search(enrollServicesBase, 1, filter, []string{
		"cn", "cACertificate", "dNSHostName", "certificateTemplates",
	})
	if err != nil {
		return fmt.Errorf("LDAP search failed: %w", err)
	}

	if len(entries) == 0 {
		return fmt.Errorf("no CA found matching '%s'", caFlags.CA)
	}

	for _, entry := range entries {
		caName := entry.GetAttributeValue("cn")
		hostname := entry.GetAttributeValue("dNSHostName")
		certBytes := entry.GetRawAttributeValue("cACertificate")

		fmt.Printf("\n[+] CA: %s\n", caName)
		fmt.Printf("    Hostname:     %s\n", hostname)

		if len(certBytes) == 0 {
			fmt.Printf("    [!] No certificate found in LDAP\n")
			continue
		}

		// Parse and display cert info
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			fmt.Printf("    [!] Failed to parse certificate: %v\n", err)
			continue
		}

		fmt.Printf("    Subject:      %s\n", cert.Subject)
		fmt.Printf("    Serial:       %s\n", cert.SerialNumber.String())
		fmt.Printf("    Not Before:   %s\n", cert.NotBefore.Format("2006-01-02"))
		fmt.Printf("    Not After:    %s\n", cert.NotAfter.Format("2006-01-02"))
		fmt.Printf("    Is CA:        %v\n", cert.IsCA)

		// Templates
		templates := entry.GetAttributeValues("certificateTemplates")
		if len(templates) > 0 {
			fmt.Printf("    Templates:    %d published\n", len(templates))
		}

		// Save as PEM
		outFile := caFlags.Output
		if outFile == "" {
			outFile = fmt.Sprintf("%s_CA.pem", caName)
		}

		pemBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certBytes,
		}
		pemData := pem.EncodeToMemory(pemBlock)

		if err := os.WriteFile(outFile, pemData, 0600); err != nil {
			return fmt.Errorf("failed to write PEM file: %w", err)
		}

		fmt.Printf("    [+] Saved to %s\n", outFile)
	}

	return nil
}
