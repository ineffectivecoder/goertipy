package cert

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	key, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if key.N.BitLen() != 2048 {
		t.Errorf("expected 2048-bit key, got %d", key.N.BitLen())
	}
}

func TestGenerateKeyPairDefault(t *testing.T) {
	key, err := GenerateKeyPair(0)
	if err != nil {
		t.Fatalf("GenerateKeyPair(0): %v", err)
	}
	if key.N.BitLen() != 2048 {
		t.Errorf("expected 2048-bit default key, got %d", key.N.BitLen())
	}
}

func TestCreateCSR(t *testing.T) {
	key, _ := GenerateKeyPair(2048)

	csr, err := CreateCSR(key, "test-user", "", "")
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	if len(csr) == 0 {
		t.Fatal("CSR is empty")
	}

	// Verify it's valid PKCS#10
	parsed, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		t.Fatalf("invalid CSR: %v", err)
	}
	if parsed.Subject.CommonName != "test-user" {
		t.Errorf("expected CN=test-user, got %s", parsed.Subject.CommonName)
	}
}

func TestCreateCSRWithUPN(t *testing.T) {
	key, _ := GenerateKeyPair(2048)

	csr, err := CreateCSR(key, "test-user", "admin@corp.local", "")
	if err != nil {
		t.Fatalf("CreateCSR with UPN: %v", err)
	}

	parsed, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		t.Fatalf("invalid CSR: %v", err)
	}

	// Verify SAN extension is present
	found := false
	for _, ext := range parsed.Extensions {
		if ext.Id.String() == "2.5.29.17" {
			found = true

			// Deep ASN.1 validation: parse the SAN extension value
			// It should be SEQUENCE { [0] { OID, [0] EXPLICIT UTF8String } }
			var rawSAN asn1.RawValue
			rest, err := asn1.Unmarshal(ext.Value, &rawSAN)
			if err != nil {
				t.Fatalf("failed to parse SAN extension: %v", err)
			}
			if len(rest) > 0 {
				t.Errorf("unexpected trailing bytes in SAN: %d", len(rest))
			}
			// SEQUENCE tag
			if rawSAN.Tag != 16 {
				t.Errorf("expected SEQUENCE (16), got tag %d", rawSAN.Tag)
			}

			// First element should be GeneralName otherName [0]
			var generalName asn1.RawValue
			_, err = asn1.Unmarshal(rawSAN.Bytes, &generalName)
			if err != nil {
				t.Fatalf("failed to parse GeneralName: %v", err)
			}
			if generalName.Tag != 0 || generalName.Class != asn1.ClassContextSpecific {
				t.Errorf("expected context-specific [0], got tag=%d class=%d", generalName.Tag, generalName.Class)
			}

			// Inside: OID then [0] EXPLICIT UTF8String
			var oid asn1.ObjectIdentifier
			rest, err = asn1.Unmarshal(generalName.Bytes, &oid)
			if err != nil {
				t.Fatalf("failed to parse UPN OID: %v", err)
			}
			upnOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
			if !oid.Equal(upnOID) {
				t.Errorf("expected UPN OID %v, got %v", upnOID, oid)
			}

			// Parse the [0] EXPLICIT wrapper
			var wrapper asn1.RawValue
			_, err = asn1.Unmarshal(rest, &wrapper)
			if err != nil {
				t.Fatalf("failed to parse UPN value wrapper: %v", err)
			}

			// Inside: UTF8String
			var upnValue string
			_, err = asn1.Unmarshal(wrapper.Bytes, &upnValue)
			if err != nil {
				t.Fatalf("failed to parse UPN UTF8String: %v", err)
			}
			if upnValue != "admin@corp.local" {
				t.Errorf("expected UPN 'admin@corp.local', got '%s'", upnValue)
			}

			break
		}
	}
	if !found {
		t.Error("expected SubjectAltName extension in CSR")
	}
}

func TestCreateCSRWithDNS(t *testing.T) {
	key, _ := GenerateKeyPair(2048)

	csr, err := CreateCSR(key, "test-user", "", "dc.corp.local")
	if err != nil {
		t.Fatalf("CreateCSR with DNS: %v", err)
	}

	parsed, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		t.Fatalf("invalid CSR: %v", err)
	}

	if len(parsed.DNSNames) == 0 || parsed.DNSNames[0] != "dc.corp.local" {
		t.Errorf("expected DNS SAN dc.corp.local, got %v", parsed.DNSNames)
	}
}

func TestPFXRoundTrip(t *testing.T) {
	// Generate a self-signed cert for testing
	key, _ := GenerateKeyPair(2048)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-cert",
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	// Save and load PFX
	tmpDir := t.TempDir()
	pfxFile := filepath.Join(tmpDir, "test.pfx")

	err = SavePFX(cert, key, nil, pfxFile, "testpass")
	if err != nil {
		t.Fatalf("SavePFX: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(pfxFile); err != nil {
		t.Fatalf("PFX file not created: %v", err)
	}

	// Load it back
	loadedKey, loadedCert, _, err := LoadPFX(pfxFile, "testpass")
	if err != nil {
		t.Fatalf("LoadPFX: %v", err)
	}

	if loadedCert.Subject.CommonName != "test-cert" {
		t.Errorf("expected CN=test-cert, got %s", loadedCert.Subject.CommonName)
	}
	if loadedKey.N.Cmp(key.N) != 0 {
		t.Error("loaded key does not match original")
	}
}
