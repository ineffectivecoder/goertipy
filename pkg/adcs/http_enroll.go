package adcs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Azure/go-ntlmssp"

	goertipycert "github.com/slacker/goertipy/pkg/cert"
)

// EnrollHTTP requests a certificate from a CA via the certsrv web enrollment
// endpoint (HTTP/HTTPS with NTLM authentication).
// This is the same mechanism used by Certipy's -web flag and enables ESC8.
func EnrollHTTP(ctx context.Context, opts *EnrollOptions) (*EnrollResult, error) {
	// Parse CA name — extract just the CA name after backslash
	caName := opts.CA
	if idx := strings.Index(caName, "\\"); idx >= 0 {
		caName = caName[idx+1:]
	}

	// Determine subject
	subject := opts.Subject
	if subject == "" {
		subject = opts.Username
	}

	// Generate key pair and CSR
	key, err := goertipycert.GenerateKeyPair(opts.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	csr, err := goertipycert.CreateCSR(key, subject, opts.UPN, opts.DNS)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	// Convert DER CSR to PEM for the web endpoint
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})

	// Build request attributes
	attrs := fmt.Sprintf("CertificateTemplate:%s", opts.Template)
	if opts.UPN != "" {
		attrs += fmt.Sprintf("\nSAN:upn=%s", opts.UPN)
	}
	if opts.DNS != "" {
		attrs += fmt.Sprintf("\nSAN:dns=%s", opts.DNS)
	}

	// Build the certsrv URL
	baseURL := strings.TrimRight(opts.WebURL, "/")

	// Create NTLM-authenticated HTTP client
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: ntlmssp.Negotiator{
			RoundTripper: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, // Self-signed CA certs are common
				},
			},
		},
	}

	// Step 1: Submit the certificate request
	submitURL := fmt.Sprintf("%s/certsrv/certfnsh.asp", baseURL)
	if opts.Debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] Submitting CSR to %s\n", submitURL)
	}

	formData := url.Values{
		"Mode":             {"newreq"},
		"CertRequest":      {string(csrPEM)},
		"CertAttrib":       {attrs},
		"TargetStoreFlags": {"0"},
		"SaveCert":         {"yes"},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", submitURL,
		strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(
		fmt.Sprintf("%s\\%s", strings.ToUpper(opts.Domain), opts.Username),
		opts.Password,
	)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if opts.Debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] Response status: %d\n", resp.StatusCode)
	}

	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("authentication failed (HTTP 401) — check credentials")
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}

	bodyStr := string(body)

	// Check for errors in response
	if strings.Contains(bodyStr, "Certificate Request Denied") {
		// Try to extract the error message
		msgRe := regexp.MustCompile(`The disposition message is "([^"]*)"`)
		if m := msgRe.FindStringSubmatch(bodyStr); len(m) > 1 {
			return nil, fmt.Errorf("certificate request denied: %s", m[1])
		}
		return nil, fmt.Errorf("certificate request denied by CA")
	}

	if strings.Contains(bodyStr, "Certificate Pending") {
		// Extract request ID from pending response
		reqIDRe := regexp.MustCompile(`Your Request Id is (\d+)`)
		if m := reqIDRe.FindStringSubmatch(bodyStr); len(m) > 1 {
			var reqID uint32
			fmt.Sscanf(m[1], "%d", &reqID)
			return &EnrollResult{
				RequestID:   reqID,
				Disposition: DispositionUnderSubmission,
				Status:      fmt.Sprintf("Certificate request pending (ID: %d) — requires manager approval", reqID),
				PrivateKey:  key,
			}, nil
		}
		return nil, fmt.Errorf("certificate pending but could not extract request ID")
	}

	// Extract request ID from issued response
	reqIDRe := regexp.MustCompile(`certnew\.cer\?ReqID=(\d+)`)
	m := reqIDRe.FindStringSubmatch(bodyStr)
	if len(m) < 2 {
		// Try alternate pattern
		reqIDRe = regexp.MustCompile(`Request Id:\s*(\d+)`)
		m = reqIDRe.FindStringSubmatch(bodyStr)
	}
	if len(m) < 2 {
		if opts.Debug {
			fmt.Fprintf(os.Stderr, "[DEBUG] Response body:\n%s\n", bodyStr)
		}
		return nil, fmt.Errorf("could not extract request ID from response")
	}

	var requestID uint32
	fmt.Sscanf(m[1], "%d", &requestID)

	if opts.Debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] Certificate issued, Request ID: %d\n", requestID)
	}

	// Step 2: Download the issued certificate
	certURL := fmt.Sprintf("%s/certsrv/certnew.cer?ReqID=%d&Enc=b64", baseURL, requestID)
	if opts.Debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] Downloading certificate from %s\n", certURL)
	}

	certReq, err := http.NewRequestWithContext(ctx, "GET", certURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create cert download request: %w", err)
	}
	certReq.SetBasicAuth(
		fmt.Sprintf("%s\\%s", strings.ToUpper(opts.Domain), opts.Username),
		opts.Password,
	)

	certResp, err := client.Do(certReq)
	if err != nil {
		return nil, fmt.Errorf("certificate download failed: %w", err)
	}
	defer certResp.Body.Close()

	certBody, err := io.ReadAll(certResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate response: %w", err)
	}

	if certResp.StatusCode != 200 {
		return nil, fmt.Errorf("certificate download returned HTTP %d", certResp.StatusCode)
	}

	// Parse the certificate — response is base64-encoded DER (PEM format)
	certDER, err := decodeCertResponse(certBody)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return &EnrollResult{
		RequestID:   requestID,
		Disposition: DispositionIssued,
		Status:      "Certificate issued",
		Certificate: cert,
		PrivateKey:  key,
	}, nil
}

// RetrieveHTTP retrieves a pending certificate by request ID via the certsrv
// web endpoint.
func RetrieveHTTP(ctx context.Context, opts *RetrieveOptions) (*EnrollResult, error) {
	baseURL := strings.TrimRight(opts.WebURL, "/")

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: ntlmssp.Negotiator{
			RoundTripper: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}

	certURL := fmt.Sprintf("%s/certsrv/certnew.cer?ReqID=%d&Enc=b64", baseURL, opts.RequestID)

	req, err := http.NewRequestWithContext(ctx, "GET", certURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.SetBasicAuth(
		fmt.Sprintf("%s\\%s", strings.ToUpper(opts.Domain), opts.Username),
		opts.Password,
	)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("authentication failed (HTTP 401)")
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("certificate download returned HTTP %d", resp.StatusCode)
	}

	certDER, err := decodeCertResponse(body)
	if err != nil {
		return nil, fmt.Errorf("failed to decode certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return &EnrollResult{
		RequestID:   opts.RequestID,
		Disposition: DispositionIssued,
		Status:      "Certificate retrieved",
		Certificate: cert,
	}, nil
}

// decodeCertResponse decodes a certificate from the certsrv response.
// The response is typically base64-encoded DER wrapped in PEM headers.
func decodeCertResponse(data []byte) ([]byte, error) {
	// Try PEM first
	block, _ := pem.Decode(data)
	if block != nil {
		return block.Bytes, nil
	}

	// Try raw base64
	cleaned := strings.TrimSpace(string(data))
	// Remove any HTML tags
	htmlRe := regexp.MustCompile(`<[^>]*>`)
	cleaned = htmlRe.ReplaceAllString(cleaned, "")
	cleaned = strings.TrimSpace(cleaned)

	der, err := base64.StdEncoding.DecodeString(cleaned)
	if err != nil {
		// Try with line breaks removed
		cleaned = strings.ReplaceAll(cleaned, "\r\n", "")
		cleaned = strings.ReplaceAll(cleaned, "\n", "")
		der, err = base64.StdEncoding.DecodeString(cleaned)
		if err != nil {
			return nil, fmt.Errorf("could not decode certificate data: %w", err)
		}
	}

	return der, nil
}
