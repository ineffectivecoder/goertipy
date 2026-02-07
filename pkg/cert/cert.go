package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"os"

	"software.sslmate.com/src/go-pkcs12"
)

// GenerateKeyPair generates an RSA key pair with the given bit size.
func GenerateKeyPair(bits int) (*rsa.PrivateKey, error) {
	if bits == 0 {
		bits = 2048
	}
	return rsa.GenerateKey(rand.Reader, bits)
}

// CreateCSR generates a PKCS#10 Certificate Signing Request.
// subject is the CN, upn is the UPN SAN override (for ESC1), dns is a DNS SAN.
func CreateCSR(key *rsa.PrivateKey, subject string, upn string, dns string) ([]byte, error) {
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: subject,
		},
	}

	// Add DNS SANs
	if dns != "" {
		template.DNSNames = []string{dns}
	}

	// Add UPN as a SAN extension (OID 1.3.6.1.4.1.311.20.2.3)
	if upn != "" {
		// UPN is encoded as an otherName in SubjectAlternativeName
		// Per RFC 5280:
		//   GeneralName ::= CHOICE { otherName [0] OtherName, ... }
		//   OtherName ::= SEQUENCE { type-id OID, value [0] EXPLICIT ANY }
		// The [0] implicit tag on GeneralName REPLACES the SEQUENCE tag.
		upnOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}

		// Encode the UPN as UTF8String
		upnUTF8, err := asn1.Marshal(upn)
		if err != nil {
			return nil, fmt.Errorf("failed to encode UPN: %w", err)
		}

		// Build OtherName SEQUENCE contents: { OID, [0] EXPLICIT UTF8String }
		otherName := struct {
			TypeID asn1.ObjectIdentifier
			Value  asn1.RawValue
		}{
			TypeID: upnOID,
			Value: asn1.RawValue{
				Tag:        0,
				Class:      asn1.ClassContextSpecific,
				IsCompound: true,
				Bytes:      upnUTF8,
			},
		}

		otherNameBytes, err := asn1.Marshal(otherName)
		if err != nil {
			return nil, fmt.Errorf("failed to encode otherName: %w", err)
		}

		// The implicit [0] tag replaces the SEQUENCE (0x30) tag.
		// otherNameBytes is a full TLV starting with 0x30 (SEQUENCE).
		// We need the inner content bytes to wrap in [0] implicit.
		var innerBytes asn1.RawValue
		if _, err := asn1.Unmarshal(otherNameBytes, &innerBytes); err != nil {
			return nil, fmt.Errorf("failed to parse otherName: %w", err)
		}

		// GeneralName otherName [0] — implicit tag wrapping the SEQUENCE content
		generalName := asn1.RawValue{
			Tag:        0,
			Class:      asn1.ClassContextSpecific,
			IsCompound: true,
			Bytes:      innerBytes.Bytes,
		}

		// SAN extension is a SEQUENCE OF GeneralName
		sanBytes, err := asn1.Marshal([]asn1.RawValue{generalName})
		if err != nil {
			return nil, fmt.Errorf("failed to encode SAN: %w", err)
		}

		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id:    asn1.ObjectIdentifier{2, 5, 29, 17}, // subjectAltName
			Value: sanBytes,
		})
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	return csr, nil
}

// SavePFX saves a certificate and private key as a PKCS#12 (.pfx) file.
func SavePFX(cert *x509.Certificate, key *rsa.PrivateKey, caCerts []*x509.Certificate, filename string, password string) error {
	pfxData, err := pkcs12.Encode(rand.Reader, key, cert, caCerts, password)
	if err != nil {
		return fmt.Errorf("failed to encode PFX: %w", err)
	}
	return os.WriteFile(filename, pfxData, 0600)
}

// LoadPFX loads a certificate and private key from a PKCS#12 (.pfx) file.
func LoadPFX(filename string, password string) (*rsa.PrivateKey, *x509.Certificate, []*x509.Certificate, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read PFX file: %w", err)
	}

	key, cert, caCerts, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode PFX: %w", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, nil, fmt.Errorf("PFX does not contain an RSA private key")
	}

	return rsaKey, cert, caCerts, nil
}

// SavePEM saves a certificate and key as separate PEM files.
func SavePEM(cert *x509.Certificate, key *rsa.PrivateKey, certFile, keyFile string) error {
	// Save certificate
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Save private key
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return os.WriteFile(keyFile, keyPEM, 0600)
}
