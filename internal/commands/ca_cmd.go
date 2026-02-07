package commands

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/slacker/goertipy/pkg/adcs"
	"github.com/slacker/goertipy/pkg/adcs/flags"
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
	Proxy    string
	Debug    bool

	// Revoke-specific
	Serial string
	Reason string

	// Config-specific
	Entry    string
	NodePath string
	JSON     bool

	// Template-specific
	Template    string
	TemplateOID string
}

var caFlags CAFlags

// NewCACommand creates the ca subcommand.
func NewCACommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ca",
		Short: "CA management operations",
		Long:  `Manage Certificate Authority — backup CA certificate, revoke certificates, dump configuration.`,
	}

	// --- backup subcommand ---
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

	// --- revoke subcommand ---
	revokeCmd := &cobra.Command{
		Use:   "revoke",
		Short: "Revoke a certificate by serial number",
		Long: `Revoke a certificate on the CA using the ICertAdminD::RevokeCertificate RPC method.
Requires CA admin privileges. The serial number should be provided in hex format.`,
		RunE: runCARevoke,
	}

	revokeCmd.Flags().StringVar(&caFlags.CA, "ca", "", "CA name (e.g., 'host\\ca-name' or 'ca-name')")
	revokeCmd.Flags().StringVar(&caFlags.Serial, "serial", "", "Certificate serial number (hex)")
	revokeCmd.Flags().StringVar(&caFlags.Reason, "reason", "unspecified", "Revocation reason (unspecified, keycompromise, cacompromise, affiliationchanged, superseded, cessation, hold)")
	revokeCmd.Flags().StringVarP(&caFlags.Username, "username", "u", "", "Username")
	revokeCmd.Flags().StringVarP(&caFlags.Password, "password", "p", "", "Password")
	revokeCmd.Flags().StringVarP(&caFlags.Hashes, "hashes", "H", "", "NTLM hash (LM:NT or :NT)")
	revokeCmd.Flags().StringVarP(&caFlags.Domain, "domain", "d", "", "Target domain")
	revokeCmd.Flags().StringVar(&caFlags.DCIP, "dc-ip", "", "CA server IP")
	revokeCmd.Flags().StringVar(&caFlags.Proxy, "proxy", "", "SOCKS5 proxy URL (e.g., socks5://127.0.0.1:1080)")
	revokeCmd.Flags().BoolVar(&caFlags.Debug, "debug", false, "Debug output")

	// --- config subcommand ---
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Dump CA configuration via RPC",
		Long: `Retrieve CA configuration entries using the ICertAdminD2::GetConfigEntry RPC method.
Dumps known configuration values such as CA type, CRL periods, validity, and policy settings.`,
		RunE: runCAConfig,
	}

	configCmd.Flags().StringVar(&caFlags.CA, "ca", "", "CA name (e.g., 'host\\ca-name' or 'ca-name')")
	configCmd.Flags().StringVar(&caFlags.Entry, "entry", "", "Specific config entry name (optional, dumps all known entries if omitted)")
	configCmd.Flags().StringVar(&caFlags.NodePath, "node-path", "", "Config node path (e.g., 'Policy')")
	configCmd.Flags().StringVarP(&caFlags.Username, "username", "u", "", "Username")
	configCmd.Flags().StringVarP(&caFlags.Password, "password", "p", "", "Password")
	configCmd.Flags().StringVarP(&caFlags.Hashes, "hashes", "H", "", "NTLM hash (LM:NT or :NT)")
	configCmd.Flags().StringVarP(&caFlags.Domain, "domain", "d", "", "Target domain")
	configCmd.Flags().StringVar(&caFlags.DCIP, "dc-ip", "", "CA server IP")
	configCmd.Flags().StringVar(&caFlags.Proxy, "proxy", "", "SOCKS5 proxy URL (e.g., socks5://127.0.0.1:1080)")
	configCmd.Flags().BoolVar(&caFlags.Debug, "debug", false, "Debug output")

	// --- list-templates subcommand ---
	listTemplatesCmd := &cobra.Command{
		Use:   "list-templates",
		Short: "List certificate templates enabled on the CA",
		Long:  `List all certificate templates currently enabled on the CA via ICertAdminD2::GetCAProperty.`,
		RunE:  runCAListTemplates,
	}
	listTemplatesCmd.Flags().StringVar(&caFlags.CA, "ca", "", "CA name")
	listTemplatesCmd.Flags().StringVarP(&caFlags.Username, "username", "u", "", "Username")
	listTemplatesCmd.Flags().StringVarP(&caFlags.Password, "password", "p", "", "Password")
	listTemplatesCmd.Flags().StringVarP(&caFlags.Hashes, "hashes", "H", "", "NTLM hash (LM:NT or :NT)")
	listTemplatesCmd.Flags().StringVarP(&caFlags.Domain, "domain", "d", "", "Target domain")
	listTemplatesCmd.Flags().StringVar(&caFlags.DCIP, "dc-ip", "", "CA server IP")
	listTemplatesCmd.Flags().StringVar(&caFlags.Proxy, "proxy", "", "SOCKS5 proxy URL")
	listTemplatesCmd.Flags().BoolVar(&caFlags.Debug, "debug", false, "Debug output")

	// --- enable-template subcommand ---
	enableTemplateCmd := &cobra.Command{
		Use:   "enable-template",
		Short: "Enable a certificate template on the CA",
		Long:  `Enable a certificate template on the CA via ICertAdminD2::SetCAProperty. Requires ManageCA rights.`,
		RunE:  runCAEnableTemplate,
	}
	enableTemplateCmd.Flags().StringVar(&caFlags.CA, "ca", "", "CA name")
	enableTemplateCmd.Flags().StringVar(&caFlags.Template, "template", "", "Template name (CN)")
	enableTemplateCmd.Flags().StringVar(&caFlags.TemplateOID, "template-oid", "", "Template OID (msPKI-Cert-Template-OID)")
	enableTemplateCmd.Flags().StringVarP(&caFlags.Username, "username", "u", "", "Username")
	enableTemplateCmd.Flags().StringVarP(&caFlags.Password, "password", "p", "", "Password")
	enableTemplateCmd.Flags().StringVarP(&caFlags.Hashes, "hashes", "H", "", "NTLM hash (LM:NT or :NT)")
	enableTemplateCmd.Flags().StringVarP(&caFlags.Domain, "domain", "d", "", "Target domain")
	enableTemplateCmd.Flags().StringVar(&caFlags.DCIP, "dc-ip", "", "CA server IP")
	enableTemplateCmd.Flags().StringVar(&caFlags.Proxy, "proxy", "", "SOCKS5 proxy URL")
	enableTemplateCmd.Flags().BoolVar(&caFlags.Debug, "debug", false, "Debug output")

	// --- disable-template subcommand ---
	disableTemplateCmd := &cobra.Command{
		Use:   "disable-template",
		Short: "Disable a certificate template on the CA",
		Long:  `Disable a certificate template on the CA via ICertAdminD2::SetCAProperty. Requires ManageCA rights.`,
		RunE:  runCADisableTemplate,
	}
	disableTemplateCmd.Flags().StringVar(&caFlags.CA, "ca", "", "CA name")
	disableTemplateCmd.Flags().StringVar(&caFlags.Template, "template", "", "Template name (CN)")
	disableTemplateCmd.Flags().StringVarP(&caFlags.Username, "username", "u", "", "Username")
	disableTemplateCmd.Flags().StringVarP(&caFlags.Password, "password", "p", "", "Password")
	disableTemplateCmd.Flags().StringVarP(&caFlags.Hashes, "hashes", "H", "", "NTLM hash (LM:NT or :NT)")
	disableTemplateCmd.Flags().StringVarP(&caFlags.Domain, "domain", "d", "", "Target domain")
	disableTemplateCmd.Flags().StringVar(&caFlags.DCIP, "dc-ip", "", "CA server IP")
	disableTemplateCmd.Flags().StringVar(&caFlags.Proxy, "proxy", "", "SOCKS5 proxy URL")
	disableTemplateCmd.Flags().BoolVar(&caFlags.Debug, "debug", false, "Debug output")

	cmd.AddCommand(backupCmd)
	cmd.AddCommand(revokeCmd)
	cmd.AddCommand(configCmd)
	cmd.AddCommand(listTemplatesCmd)
	cmd.AddCommand(enableTemplateCmd)
	cmd.AddCommand(disableTemplateCmd)
	return cmd
}

// parseCAAuth extracts domain/username from flags and prompts for password if needed.
func parseCAAuth() (username, domain, password, ntHash string, err error) {
	username = caFlags.Username
	domain = caFlags.Domain
	password = caFlags.Password

	if username == "" {
		return "", "", "", "", fmt.Errorf("username is required (-u)")
	}

	// Extract domain from username if not specified
	if domain == "" {
		if strings.Contains(username, "@") {
			parts := strings.SplitN(username, "@", 2)
			domain = parts[1]
			username = parts[0]
		} else if strings.Contains(username, "\\") {
			parts := strings.SplitN(username, "\\", 2)
			domain = parts[0]
			username = parts[1]
		} else {
			return "", "", "", "", fmt.Errorf("domain is required (-d) or use user@domain format")
		}
	}

	// Parse hashes
	if caFlags.Hashes != "" {
		_, ntHash, err = goertipyldap.ParseHashes(caFlags.Hashes)
		if err != nil {
			return "", "", "", "", fmt.Errorf("invalid hash format: %w", err)
		}
	}

	// Prompt for password if needed
	if password == "" && ntHash == "" {
		fmt.Print("Password: ")
		passwordBytes, perr := term.ReadPassword(int(os.Stdin.Fd()))
		if perr != nil {
			return "", "", "", "", fmt.Errorf("failed to read password: %w", perr)
		}
		fmt.Println()
		password = string(passwordBytes)
	}

	return username, domain, password, ntHash, nil
}

func runCARevoke(cmd *cobra.Command, args []string) error {
	if caFlags.DCIP == "" {
		return fmt.Errorf("CA server IP is required (--dc-ip)")
	}
	if caFlags.CA == "" {
		return fmt.Errorf("CA name is required (--ca)")
	}
	if caFlags.Serial == "" {
		return fmt.Errorf("serial number is required (--serial)")
	}

	// Parse revocation reason
	reason, err := adcs.RevocationReasonFromString(caFlags.Reason)
	if err != nil {
		return err
	}

	username, domain, password, ntHash, err := parseCAAuth()
	if err != nil {
		return err
	}

	serial := adcs.NormalizeSerialNumber(caFlags.Serial)
	reasonName := adcs.RevocationReasonNames[reason]

	fmt.Printf("[*] Revoking certificate\n")
	fmt.Printf("    CA:     %s\n", caFlags.CA)
	fmt.Printf("    Serial: %s\n", serial)
	fmt.Printf("    Reason: %s (%d)\n", reasonName, reason)
	fmt.Printf("[*] Connecting to %s via RPC...\n", caFlags.DCIP)

	ctx := context.Background()
	adminClient, err := adcs.ConnectAdmin(ctx, &adcs.AdminOptions{
		Server:   caFlags.DCIP,
		Username: username,
		Password: password,
		NTHash:   ntHash,
		Domain:   domain,
		ProxyURL: caFlags.Proxy,
		Debug:    caFlags.Debug,
	})
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer adminClient.Close()

	err = adminClient.RevokeCertificate(ctx, &adcs.RevokeOptions{
		CA:           caFlags.CA,
		SerialNumber: serial,
		Reason:       reason,
	})
	if err != nil {
		return fmt.Errorf("revocation failed: %w", err)
	}

	fmt.Printf("[+] Certificate %s revoked successfully (reason: %s)\n", serial, reasonName)
	return nil
}

func runCAConfig(cmd *cobra.Command, args []string) error {
	if caFlags.DCIP == "" {
		return fmt.Errorf("CA server IP is required (--dc-ip)")
	}
	if caFlags.CA == "" {
		return fmt.Errorf("CA name is required (--ca)")
	}

	username, domain, password, ntHash, err := parseCAAuth()
	if err != nil {
		return err
	}

	fmt.Printf("[*] Dumping configuration for CA: %s\n", caFlags.CA)
	fmt.Printf("[*] Connecting to %s via RPC...\n", caFlags.DCIP)

	ctx := context.Background()
	adminClient, err := adcs.ConnectAdmin(ctx, &adcs.AdminOptions{
		Server:   caFlags.DCIP,
		Username: username,
		Password: password,
		NTHash:   ntHash,
		Domain:   domain,
		ProxyURL: caFlags.Proxy,
		Debug:    caFlags.Debug,
	})
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer adminClient.Close()

	// Single entry mode
	if caFlags.Entry != "" {
		entry, err := adminClient.GetConfigEntry(ctx, caFlags.CA, caFlags.NodePath, caFlags.Entry)
		if err != nil {
			return err
		}
		printConfigEntry(entry)
		return nil
	}

	// Dump all known entries
	entries, err := adminClient.DumpConfig(ctx, caFlags.CA, caFlags.Debug)
	if err != nil {
		return err
	}

	if len(entries) == 0 {
		fmt.Printf("[!] No configuration entries retrieved\n")
		return nil
	}

	fmt.Printf("\n[+] CA Configuration:\n")
	fmt.Printf("    %-40s %s\n", "Entry", "Value")
	fmt.Printf("    %-40s %s\n", strings.Repeat("-", 40), strings.Repeat("-", 40))
	for _, e := range entries {
		printConfigEntry(&e)
	}

	return nil
}

func printConfigEntry(e *adcs.ConfigEntry) {
	path := e.Entry
	if e.NodePath != "" {
		path = e.NodePath + "\\" + e.Entry
	}

	// Translate known numeric values to human-readable form
	display := formatConfigValue(path, e.Value)
	fmt.Printf("    %-40s %s\n", path, display)
}

// formatConfigValue translates known config entry values to human-readable form.
func formatConfigValue(path string, value interface{}) string {
	// Try to extract uint32 for flag/enum translation
	var numVal uint32
	var isNum bool
	switch v := value.(type) {
	case uint32:
		numVal = v
		isNum = true
	case int32:
		numVal = uint32(v)
		isNum = true
	case uint64:
		numVal = uint32(v)
		isNum = true
	case int64:
		numVal = uint32(v)
		isNum = true
	case int:
		numVal = uint32(v)
		isNum = true
	}

	if !isNum {
		return fmt.Sprintf("%v", value)
	}

	switch path {
	case "CAType":
		if name, ok := flags.CATypeNames[numVal]; ok {
			return fmt.Sprintf("%s (%d)", name, numVal)
		}
	case "Policy\\EditFlags":
		setFlags := flags.GetSetFlags(numVal, flags.EditFlagNames)
		if len(setFlags) > 0 {
			sort.Strings(setFlags)
			return fmt.Sprintf("0x%06X (%s)", numVal, strings.Join(setFlags, " | "))
		}
		return fmt.Sprintf("0x%06X", numVal)
	case "Policy\\RequestDisposition":
		if name, ok := flags.RequestDispositionNames[numVal]; ok {
			return fmt.Sprintf("%s (%d)", name, numVal)
		}
	}

	return fmt.Sprintf("%v", value)
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

func runCAListTemplates(cmd *cobra.Command, args []string) error {
	if caFlags.DCIP == "" {
		return fmt.Errorf("CA server IP is required (--dc-ip)")
	}
	if caFlags.CA == "" {
		return fmt.Errorf("CA name is required (--ca)")
	}

	username, domain, password, ntHash, err := parseCAAuth()
	if err != nil {
		return err
	}

	fmt.Printf("[*] Listing templates on CA: %s\n", caFlags.CA)
	fmt.Printf("[*] Connecting to %s via RPC...\n", caFlags.DCIP)

	ctx := context.Background()
	adminClient, err := adcs.ConnectAdmin(ctx, &adcs.AdminOptions{
		Server:   caFlags.DCIP,
		Username: username,
		Password: password,
		NTHash:   ntHash,
		Domain:   domain,
		ProxyURL: caFlags.Proxy,
		Debug:    caFlags.Debug,
	})
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer adminClient.Close()

	templates, err := adminClient.GetTemplates(ctx, caFlags.CA)
	if err != nil {
		return fmt.Errorf("failed to get templates: %w", err)
	}

	if len(templates) == 0 {
		fmt.Println("[*] No certificate templates enabled on this CA")
		return nil
	}

	fmt.Printf("[+] Enabled certificate templates on %s:\n", caFlags.CA)
	for i := 0; i < len(templates)-1; i += 2 {
		fmt.Printf("    %-40s %s\n", templates[i], templates[i+1])
	}
	return nil
}

func runCAEnableTemplate(cmd *cobra.Command, args []string) error {
	if caFlags.DCIP == "" {
		return fmt.Errorf("CA server IP is required (--dc-ip)")
	}
	if caFlags.CA == "" {
		return fmt.Errorf("CA name is required (--ca)")
	}
	if caFlags.Template == "" {
		return fmt.Errorf("template name is required (--template)")
	}
	if caFlags.TemplateOID == "" {
		return fmt.Errorf("template OID is required (--template-oid)")
	}

	username, domain, password, ntHash, err := parseCAAuth()
	if err != nil {
		return err
	}

	fmt.Printf("[*] Enabling template %q on CA: %s\n", caFlags.Template, caFlags.CA)
	fmt.Printf("[*] Connecting to %s via RPC...\n", caFlags.DCIP)

	ctx := context.Background()
	adminClient, err := adcs.ConnectAdmin(ctx, &adcs.AdminOptions{
		Server:   caFlags.DCIP,
		Username: username,
		Password: password,
		NTHash:   ntHash,
		Domain:   domain,
		ProxyURL: caFlags.Proxy,
		Debug:    caFlags.Debug,
	})
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer adminClient.Close()

	err = adminClient.EnableTemplate(ctx, caFlags.CA, caFlags.Template, caFlags.TemplateOID)
	if err != nil {
		return fmt.Errorf("failed to enable template: %w", err)
	}

	fmt.Printf("[+] Successfully enabled %q on %s\n", caFlags.Template, caFlags.CA)
	return nil
}

func runCADisableTemplate(cmd *cobra.Command, args []string) error {
	if caFlags.DCIP == "" {
		return fmt.Errorf("CA server IP is required (--dc-ip)")
	}
	if caFlags.CA == "" {
		return fmt.Errorf("CA name is required (--ca)")
	}
	if caFlags.Template == "" {
		return fmt.Errorf("template name is required (--template)")
	}

	username, domain, password, ntHash, err := parseCAAuth()
	if err != nil {
		return err
	}

	fmt.Printf("[*] Disabling template %q on CA: %s\n", caFlags.Template, caFlags.CA)
	fmt.Printf("[*] Connecting to %s via RPC...\n", caFlags.DCIP)

	ctx := context.Background()
	adminClient, err := adcs.ConnectAdmin(ctx, &adcs.AdminOptions{
		Server:   caFlags.DCIP,
		Username: username,
		Password: password,
		NTHash:   ntHash,
		Domain:   domain,
		ProxyURL: caFlags.Proxy,
		Debug:    caFlags.Debug,
	})
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer adminClient.Close()

	err = adminClient.DisableTemplate(ctx, caFlags.CA, caFlags.Template)
	if err != nil {
		return fmt.Errorf("failed to disable template: %w", err)
	}

	fmt.Printf("[+] Successfully disabled %q on %s\n", caFlags.Template, caFlags.CA)
	return nil
}
