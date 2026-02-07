package adcs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
)

func TestDecodeCertResponse_PEM(t *testing.T) {
	// Generate a real self-signed cert for testing
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	der, err := decodeCertResponse(pemData)
	if err != nil {
		t.Fatalf("decodeCertResponse(PEM): %v", err)
	}
	if len(der) == 0 {
		t.Fatal("decoded DER is empty")
	}
	if der[0] != 0x30 {
		t.Errorf("expected DER to start with 0x30, got 0x%02x", der[0])
	}
}

func TestDecodeCertResponse_Base64(t *testing.T) {
	// Base64 of a minimal DER-encoded test structure
	// This is just "SEQUENCE { INTEGER 42 }" = 30 03 02 01 2a
	b64Data := []byte("MAMCAQI=")

	der, err := decodeCertResponse(b64Data)
	if err != nil {
		t.Fatalf("decodeCertResponse(base64): %v", err)
	}
	if len(der) == 0 {
		t.Fatal("decoded DER is empty")
	}
	if der[0] != 0x30 {
		t.Errorf("expected DER to start with 0x30, got 0x%02x", der[0])
	}
}

func TestDecodeCertResponse_HTMLWrapped(t *testing.T) {
	// Simulate certsrv response with HTML tags around base64
	htmlData := []byte("<html><body>MAMCAQI=</body></html>")

	der, err := decodeCertResponse(htmlData)
	if err != nil {
		t.Fatalf("decodeCertResponse(HTML): %v", err)
	}
	if len(der) == 0 {
		t.Fatal("decoded DER is empty")
	}
}

func TestDecodeCertResponse_Invalid(t *testing.T) {
	_, err := decodeCertResponse([]byte("not valid base64 or pem!!!"))
	if err == nil {
		t.Error("expected error for invalid cert data")
	}
}
