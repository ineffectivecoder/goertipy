package commands

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	goertipycert "github.com/slacker/goertipy/pkg/cert"
	"github.com/spf13/cobra"
)

type CertFlags struct {
	PFXPass string
}

var certFlags CertFlags

// NewCertCommand creates the cert subcommand.
func NewCertCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Certificate utilities",
		Long:  `Inspect and manage certificates.`,
	}

	showCmd := &cobra.Command{
		Use:   "show [file]",
		Short: "Display certificate details from a PFX or PEM file",
		Args:  cobra.ExactArgs(1),
		RunE:  runCertShow,
	}

	showCmd.Flags().StringVar(&certFlags.PFXPass, "pfx-pass", "", "PFX password (default: empty)")

	cmd.AddCommand(showCmd)
	return cmd
}

func runCertShow(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Try PEM first
	block, _ := pem.Decode(data)
	if block != nil && block.Type == "CERTIFICATE" {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse PEM certificate: %w", err)
		}
		printCertInfo(cert, nil)
		return nil
	}

	// Try PFX
	key, cert, caCerts, err := goertipycert.LoadPFX(filePath, certFlags.PFXPass)
	if err != nil {
		return fmt.Errorf("failed to parse file (tried PEM and PFX): %w", err)
	}

	printCertInfo(cert, caCerts)

	if key != nil {
		fmt.Printf("\n[*] Private Key\n")
		fmt.Printf("    Algorithm:    RSA\n")
		fmt.Printf("    Key Size:     %d bits\n", key.N.BitLen())
	}

	return nil
}

func printCertInfo(cert *x509.Certificate, caCerts []*x509.Certificate) {
	fmt.Printf("[*] Certificate\n")
	fmt.Printf("    Subject:      %s\n", cert.Subject)
	fmt.Printf("    Issuer:       %s\n", cert.Issuer)
	fmt.Printf("    Serial:       %s\n", cert.SerialNumber.String())
	fmt.Printf("    Not Before:   %s\n", cert.NotBefore.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("    Not After:    %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 UTC"))
	fmt.Printf("    Signature:    %s\n", cert.SignatureAlgorithm)
	fmt.Printf("    Public Key:   %s (%d bits)\n", cert.PublicKeyAlgorithm, certKeyBits(cert))

	// Key Usage
	if cert.KeyUsage != 0 {
		fmt.Printf("    Key Usage:    %s\n", formatKeyUsage(cert.KeyUsage))
	}

	// Extended Key Usage
	if len(cert.ExtKeyUsage) > 0 || len(cert.UnknownExtKeyUsage) > 0 {
		fmt.Printf("    EKUs:\n")
		for _, eku := range cert.ExtKeyUsage {
			fmt.Printf("                  %s\n", ekuName(eku))
		}
		for _, oid := range cert.UnknownExtKeyUsage {
			fmt.Printf("                  %s\n", oid.String())
		}
	}

	// SANs
	hasSAN := false
	if len(cert.DNSNames) > 0 {
		hasSAN = true
		fmt.Printf("    DNS SANs:\n")
		for _, dns := range cert.DNSNames {
			fmt.Printf("                  %s\n", dns)
		}
	}
	if len(cert.EmailAddresses) > 0 {
		hasSAN = true
		fmt.Printf("    Email SANs:\n")
		for _, email := range cert.EmailAddresses {
			fmt.Printf("                  %s\n", email)
		}
	}
	if len(cert.IPAddresses) > 0 {
		hasSAN = true
		fmt.Printf("    IP SANs:\n")
		for _, ip := range cert.IPAddresses {
			fmt.Printf("                  %s\n", ip.String())
		}
	}

	// Check for UPN in extensions (OID 2.5.29.17)
	for _, ext := range cert.Extensions {
		if ext.Id.String() == "2.5.29.17" && !hasSAN {
			fmt.Printf("    SANs:         (present, may contain UPN/otherName)\n")
		}
	}

	// CA certs
	if len(caCerts) > 0 {
		fmt.Printf("\n[*] CA Chain (%d certificates)\n", len(caCerts))
		for i, ca := range caCerts {
			fmt.Printf("    [%d] %s\n", i, ca.Subject)
		}
	}
}

func certKeyBits(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	default:
		return 0
	}
}

func formatKeyUsage(ku x509.KeyUsage) string {
	var usages []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	return strings.Join(usages, ", ")
}

func ekuName(eku x509.ExtKeyUsage) string {
	switch eku {
	case x509.ExtKeyUsageAny:
		return "Any Purpose"
	case x509.ExtKeyUsageServerAuth:
		return "Server Authentication (1.3.6.1.5.5.7.3.1)"
	case x509.ExtKeyUsageClientAuth:
		return "Client Authentication (1.3.6.1.5.5.7.3.2)"
	case x509.ExtKeyUsageCodeSigning:
		return "Code Signing (1.3.6.1.5.5.7.3.3)"
	case x509.ExtKeyUsageEmailProtection:
		return "Email Protection (1.3.6.1.5.5.7.3.4)"
	case x509.ExtKeyUsageOCSPSigning:
		return "OCSP Signing (1.3.6.1.5.5.7.3.9)"
	case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
		return "Microsoft Server Gated Crypto"
	default:
		return fmt.Sprintf("Unknown EKU (%d)", eku)
	}
}
