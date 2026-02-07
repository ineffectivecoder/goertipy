package adcs

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/csra"
	icertadmind "github.com/oiweiwei/go-msrpc/msrpc/dcom/csra/icertadmind/v0"
	icertadmind2 "github.com/oiweiwei/go-msrpc/msrpc/dcom/csra/icertadmind2/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iactivation/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iobjectexporter/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/oaut"
	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	winreg "github.com/oiweiwei/go-msrpc/msrpc/rrp/winreg/v1"
	"github.com/oiweiwei/go-msrpc/msrpc/well_known"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
	"golang.org/x/net/proxy"
)

// CertAdminCLSID is the CLSID for the CertAdmin DCOM class.
// From certipy: CLSID_ICertAdminD = d99e6e73-fc88-11d0-b498-00a0c90312f3
// (IID=d99e6e71, ICertRequestD IID=d99e6e72, CertAdmin CLSID=d99e6e73, CertRequestD CLSID=d99e6e74)
var CertAdminCLSID = &dcom.ClassID{
	Data1: 0xd99e6e73,
	Data2: 0xfc88,
	Data3: 0x11d0,
	Data4: []byte{0xb4, 0x98, 0x00, 0xa0, 0xc9, 0x03, 0x12, 0xf3},
}

// Revocation reason codes from MS-CSRA / RFC 3280 §5.3.1
const (
	RevokeReasonUnspecified        uint32 = 0
	RevokeReasonKeyCompromise      uint32 = 1
	RevokeReasonCACompromise       uint32 = 2
	RevokeReasonAffiliationChanged uint32 = 3
	RevokeReasonSuperseded         uint32 = 4
	RevokeReasonCessationOfOp      uint32 = 5
	RevokeReasonCertificateHold    uint32 = 6
	RevokeReasonRemoveFromCRL      uint32 = 8
	RevokeReasonReleaseFromHold    uint32 = 0xffffffff
)

// CR_PROP_TEMPLATES is the property ID for certificate templates on a CA.
const CR_PROP_TEMPLATES int32 = 0x1D

// PROPTYPE_STRING indicates Unicode string data in CA property requests.
const PROPTYPE_STRING int32 = 4

// RevocationReasonNames maps reason codes to human-readable names.
var RevocationReasonNames = map[uint32]string{
	RevokeReasonUnspecified:        "Unspecified",
	RevokeReasonKeyCompromise:      "Key Compromise",
	RevokeReasonCACompromise:       "CA Compromise",
	RevokeReasonAffiliationChanged: "Affiliation Changed",
	RevokeReasonSuperseded:         "Superseded",
	RevokeReasonCessationOfOp:      "Cessation of Operation",
	RevokeReasonCertificateHold:    "Certificate Hold",
	RevokeReasonRemoveFromCRL:      "Remove from CRL",
	RevokeReasonReleaseFromHold:    "Release from Hold",
}

// RevocationReasonFromString converts a string name/number to a reason code.
func RevocationReasonFromString(s string) (uint32, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "unspecified", "0":
		return RevokeReasonUnspecified, nil
	case "keycompromise", "key_compromise", "key-compromise", "1":
		return RevokeReasonKeyCompromise, nil
	case "cacompromise", "ca_compromise", "ca-compromise", "2":
		return RevokeReasonCACompromise, nil
	case "affiliationchanged", "affiliation_changed", "affiliation-changed", "3":
		return RevokeReasonAffiliationChanged, nil
	case "superseded", "4":
		return RevokeReasonSuperseded, nil
	case "cessation", "cessation_of_operation", "cessation-of-operation", "5":
		return RevokeReasonCessationOfOp, nil
	case "hold", "certificate_hold", "certificate-hold", "6":
		return RevokeReasonCertificateHold, nil
	case "removefromcrl", "remove_from_crl", "remove-from-crl", "8":
		return RevokeReasonRemoveFromCRL, nil
	case "unhold", "release", "release_from_hold", "release-from-hold":
		return RevokeReasonReleaseFromHold, nil
	default:
		return 0, fmt.Errorf("unknown revocation reason: %q (valid: unspecified, keycompromise, cacompromise, affiliationchanged, superseded, cessation, hold, removefromcrl, unhold)", s)
	}
}

// NormalizeSerialNumber cleans up a serial number string: removes colons,
// spaces, and "0x" prefix, and uppercases it.
func NormalizeSerialNumber(serial string) string {
	serial = strings.TrimPrefix(serial, "0x")
	serial = strings.TrimPrefix(serial, "0X")
	serial = strings.ReplaceAll(serial, ":", "")
	serial = strings.ReplaceAll(serial, " ", "")
	return strings.ToUpper(serial)
}

// AdminClient wraps the ICertAdminD/D2 DCOM interfaces for CA administration.
// Uses proper DCOM object activation via RemoteActivation on port 135.
type AdminClient struct {
	adminD     icertadmind.CertAdminDClient
	adminD2    icertadmind2.CertAdminD2Client
	ipidD      *dcom.IPID // IPID for ICertAdminD
	ipidD2     *dcom.IPID // IPID for ICertAdminD2
	comVersion *dcom.COMVersion
	conns      []dcerpc.Conn
	server     string // server address for lazy winreg connection
}

// AdminOptions holds connection options for the admin client.
type AdminOptions struct {
	Server   string
	Username string
	Password string
	NTHash   string
	Domain   string
	ProxyURL string // SOCKS5 proxy URL (e.g., socks5://127.0.0.1:1080)
	Debug    bool
}

// ConnectAdmin establishes a DCOM connection to the CA's ICertAdminD/D2
// interfaces using proper DCOM object activation:
//  1. Dial port 135 (OX resolver well-known endpoint)
//  2. ObjectExporter.ServerAlive2 to get COM version
//  3. Activation.RemoteActivation with CertAdmin CLSID and both IIDs
//  4. Dial the returned OXID bindings
//  5. Create individual interface clients with correct IPIDs
func ConnectAdmin(ctx context.Context, opts *AdminOptions) (*AdminClient, error) {
	// Register credentials for NTLM.
	if opts.Password != "" {
		gssapi.AddCredential(credential.NewFromPassword(opts.Username, opts.Password,
			credential.Domain(strings.ToUpper(opts.Domain))))
	} else if opts.NTHash != "" {
		hashBytes, err := hex.DecodeString(opts.NTHash)
		if err != nil {
			return nil, fmt.Errorf("invalid NT hash hex: %w", err)
		}
		gssapi.AddCredential(credential.NewFromNTHashBytes(opts.Username, hashBytes,
			credential.Domain(strings.ToUpper(opts.Domain))))
	} else {
		return nil, fmt.Errorf("either password or NT hash is required")
	}
	gssapi.AddMechanism(ssp.NTLM)

	ctx = gssapi.NewSecurityContext(ctx)

	baseOpts := []dcerpc.Option{
		dcerpc.WithSeal(),
		dcerpc.WithTargetName(opts.Server),
	}

	// If a SOCKS proxy is configured, create a dialer and inject it.
	if opts.ProxyURL != "" {
		proxyDialer, err := newProxyDialer(opts.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("proxy setup failed: %w", err)
		}
		baseOpts = append(baseOpts, dcerpc.WithDialer(proxyDialer))
		if opts.Debug {
			fmt.Fprintf(os.Stderr, "[DEBUG] Using SOCKS proxy: %s\n", opts.ProxyURL)
		}
	}

	admin := &AdminClient{}

	// Step 1: Dial port 135 (well-known OX resolver endpoint).
	if opts.Debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] Connecting to OX resolver on %s:135\n", opts.Server)
	}
	cc, err := dcerpc.Dial(ctx, opts.Server, append(baseOpts, well_known.EndpointMapper())...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial OX resolver on %s: %w", opts.Server, err)
	}
	admin.conns = append(admin.conns, cc)

	// Step 2: ObjectExporter.ServerAlive2 to get COM version and bindings.
	if opts.Debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] Calling ServerAlive2\n")
	}
	oxCli, err := iobjectexporter.NewObjectExporterClient(ctx, cc, baseOpts...)
	if err != nil {
		admin.Close()
		return nil, fmt.Errorf("failed to create ObjectExporter client: %w", err)
	}

	srv, err := oxCli.ServerAlive2(ctx, &iobjectexporter.ServerAlive2Request{})
	if err != nil {
		admin.Close()
		return nil, fmt.Errorf("ServerAlive2 failed: %w", err)
	}
	admin.comVersion = srv.COMVersion
	if opts.Debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] COM version: %d.%d\n",
			srv.COMVersion.MajorVersion, srv.COMVersion.MinorVersion)
	}

	// Step 3: RemoteActivation with CertAdmin CLSID and both IIDs.
	if opts.Debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] Activating CertAdmin DCOM object (CLSID: %v)\n", CertAdminCLSID)
	}
	iactCli, err := iactivation.NewActivationClient(ctx, cc, baseOpts...)
	if err != nil {
		admin.Close()
		return nil, fmt.Errorf("failed to create Activation client: %w", err)
	}

	act, err := iactCli.RemoteActivation(ctx, &iactivation.RemoteActivationRequest{
		ORPCThis: &dcom.ORPCThis{Version: srv.COMVersion},
		ClassID:  CertAdminCLSID.GUID(),
		IIDs: []*dcom.IID{
			icertadmind.CertAdminDIID,
			icertadmind2.CertAdminD2IID,
		},
		// 7 = ncacn_ip_tcp, 15 = ncacn_np
		RequestedProtocolSequences: []uint16{7, 15},
	})
	if err != nil {
		admin.Close()
		return nil, fmt.Errorf("RemoteActivation failed: %w", err)
	}
	if act.HResult != 0 {
		admin.Close()
		return nil, fmt.Errorf("RemoteActivation returned HRESULT 0x%08x", act.HResult)
	}

	if len(act.InterfaceData) < 2 {
		admin.Close()
		return nil, fmt.Errorf("RemoteActivation returned %d interfaces, expected 2", len(act.InterfaceData))
	}

	admin.ipidD = act.InterfaceData[0].IPID()
	admin.ipidD2 = act.InterfaceData[1].IPID()

	if opts.Debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] DCOM activation successful\n")
		fmt.Fprintf(os.Stderr, "[DEBUG]   ICertAdminD  IPID: %v\n", admin.ipidD)
		fmt.Fprintf(os.Stderr, "[DEBUG]   ICertAdminD2 IPID: %v\n", admin.ipidD2)
	}

	// Step 4: Dial the OXID bindings (dynamic TCP port returned by activation).
	wcc, err := dcerpc.Dial(ctx, opts.Server, append(baseOpts,
		act.OXIDBindings.EndpointsByProtocol("ncacn_ip_tcp")...)...)
	if err != nil {
		admin.Close()
		return nil, fmt.Errorf("failed to dial OXID endpoint: %w", err)
	}
	admin.conns = append(admin.conns, wcc)

	// Step 5: Create individual interface clients.
	ctx = gssapi.NewSecurityContext(ctx)

	adminD, err := icertadmind.NewCertAdminDClient(ctx, wcc, baseOpts...)
	if err != nil {
		admin.Close()
		return nil, fmt.Errorf("failed to create ICertAdminD client: %w", err)
	}
	admin.adminD = adminD

	adminD2, err := icertadmind2.NewCertAdminD2Client(ctx, wcc, baseOpts...)
	if err != nil {
		admin.Close()
		return nil, fmt.Errorf("failed to create ICertAdminD2 client: %w", err)
	}
	admin.adminD2 = adminD2

	admin.server = opts.Server

	if opts.Debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] CSRA admin client created successfully\n")
	}

	return admin, nil
}

// Close releases all admin client connections.
func (a *AdminClient) Close() {
	for _, cc := range a.conns {
		cc.Close(context.Background())
	}
}

// RevokeOptions holds parameters for certificate revocation.
type RevokeOptions struct {
	// CA is the CA authority name (e.g., "host\ca-name" or just "ca-name").
	CA string
	// SerialNumber is the certificate serial number in hex.
	SerialNumber string
	// Reason is the revocation reason code.
	Reason uint32
	// RevokeDate is the effective revocation date. Zero value means immediate.
	RevokeDate time.Time
}

// RevokeCertificate revokes a certificate on the CA by serial number.
func (a *AdminClient) RevokeCertificate(ctx context.Context, opts *RevokeOptions) error {
	serial := NormalizeSerialNumber(opts.SerialNumber)
	if serial == "" {
		return fmt.Errorf("serial number is required")
	}

	// Validate hex
	if _, err := hex.DecodeString(serial); err != nil {
		return fmt.Errorf("invalid serial number hex %q: %w", serial, err)
	}

	// Extract CA authority name (strip host\ prefix if present).
	authority := opts.CA
	if idx := strings.LastIndex(authority, "\\"); idx >= 0 {
		authority = authority[idx+1:]
	}

	// Build FILETIME. Zero FILETIME = revoke immediately.
	var ft *dtyp.Filetime
	if !opts.RevokeDate.IsZero() {
		ft = &dtyp.Filetime{}
		// Convert to Windows FILETIME (100-nanosecond intervals since 1601-01-01).
		epoch := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
		d := opts.RevokeDate.Sub(epoch)
		intervals := d.Nanoseconds() / 100
		ft.LowDateTime = uint32(intervals & 0xFFFFFFFF)
		ft.HighDateTime = uint32(intervals >> 32)
	} else {
		ft = &dtyp.Filetime{} // zero = immediate
	}

	_, err := a.adminD.RevokeCertificate(ctx, &icertadmind.RevokeCertificateRequest{
		This:         &dcom.ORPCThis{Version: a.comVersion},
		Authority:    authority,
		SerialNumber: serial,
		Reason:       opts.Reason,
		FileTime:     ft,
	}, dcom.WithIPID(a.ipidD))
	if err != nil {
		return fmt.Errorf("RevokeCertificate RPC failed: %s", formatRPCError(err))
	}

	return nil
}

// ConfigEntry represents a single CA configuration entry.
type ConfigEntry struct {
	NodePath string
	Entry    string
	Value    interface{}
}

// Known config entries for DumpConfig.
// NOTE: Entries returning VT_ARRAY|VT_BSTR (string arrays) are excluded because
// go-msrpc v1.2.14 panics on SafeArray VARIANT deserialization.
// Excluded: CRLPublicationURLs, CACertPublicationURLs, EnableRequestExtensionList,
// DisableExtensionList.
var knownConfigEntries = []struct {
	NodePath    string
	Entry       string
	Description string
}{
	{"", "CAType", "CA Type"},
	{"", "CRLPeriod", "CRL Period"},
	{"", "CRLPeriodUnits", "CRL Period Units"},
	{"", "CRLDeltaPeriod", "Delta CRL Period"},
	{"", "CRLDeltaPeriodUnits", "Delta CRL Period Units"},
	{"", "ValidityPeriod", "Default Validity Period"},
	{"", "ValidityPeriodUnits", "Default Validity Period Units"},
	{"Policy", "EditFlags", "Policy Edit Flags"},
	{"Policy", "RequestDisposition", "Request Disposition"},
}

// GetConfigEntry retrieves a single configuration entry from the CA.
func (a *AdminClient) GetConfigEntry(ctx context.Context, authority, nodePath, entry string) (*ConfigEntry, error) {
	// Strip host\ prefix.
	if idx := strings.LastIndex(authority, "\\"); idx >= 0 {
		authority = authority[idx+1:]
	}

	resp, err := a.adminD2.GetConfigEntry(ctx, &icertadmind2.GetConfigEntryRequest{
		This:      &dcom.ORPCThis{Version: a.comVersion},
		Authority: authority,
		NodePath:  nodePath,
		Entry:     entry,
	}, dcom.WithIPID(a.ipidD2))
	if err != nil {
		return nil, fmt.Errorf("GetConfigEntry(%s\\%s): %s", nodePath, entry, formatRPCError(err))
	}

	// Extract value from VARIANT, unwrapping BSTR strings.
	var value interface{}
	if resp.Variant != nil && resp.Variant.VarUnion != nil {
		value = extractVariantValue(resp.Variant.VarUnion)
	}

	return &ConfigEntry{
		NodePath: nodePath,
		Entry:    entry,
		Value:    value,
	}, nil
}

// DumpConfig retrieves all known configuration entries from the CA.
// Entries that fail via CSRA (e.g., not found) are retried via RRP (Remote Registry).
func (a *AdminClient) DumpConfig(ctx context.Context, authority string, debug bool) ([]ConfigEntry, error) {
	var entries []ConfigEntry
	var failedCSRA []struct {
		NodePath, Entry, Description string
	}

	for _, known := range knownConfigEntries {
		entry, err := a.safeGetConfigEntry(ctx, authority, known.NodePath, known.Entry)
		if err != nil {
			if debug {
				fmt.Fprintf(os.Stderr, "[DEBUG] CSRA failed for %s\\%s: %v\n", known.NodePath, known.Entry, err)
			}
			failedCSRA = append(failedCSRA, struct {
				NodePath, Entry, Description string
			}{known.NodePath, known.Entry, known.Description})
			continue
		}
		entries = append(entries, *entry)
	}

	// Fallback to RRP (Remote Registry) for entries that CSRA couldn't provide.
	if len(failedCSRA) > 0 {
		rrpEntries, err := a.registryFallbackConfig(ctx, authority, failedCSRA, debug)
		if err != nil {
			if debug {
				fmt.Fprintf(os.Stderr, "[DEBUG] RRP fallback failed: %v\n", err)
			}
		} else {
			entries = append(entries, rrpEntries...)
		}
	}

	return entries, nil
}

// safeGetConfigEntry wraps GetConfigEntry with panic recovery for go-msrpc
// NDR deserialization bugs (e.g., SafeArray responses cause panics).
func (a *AdminClient) safeGetConfigEntry(ctx context.Context, authority, nodePath, entry string) (result *ConfigEntry, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("NDR deserialization panic for %s\\%s: %v", nodePath, entry, r)
		}
	}()
	return a.GetConfigEntry(ctx, authority, nodePath, entry)
}

// rrpStr creates a null-terminated winreg.UnicodeString for RRP operations.
// The RRP protocol requires null-terminated strings, but go-msrpc's
// UnicodeString marshal doesn't auto-add the null terminator.
func rrpStr(s string) *winreg.UnicodeString {
	return &winreg.UnicodeString{Buffer: s + "\x00"}
}

// registryFallbackConfig reads CA config entries from the remote registry via RRP
// when CSRA's GetConfigEntry fails (typically with ERROR_FILE_NOT_FOUND).
// Registry base key: HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA-name>
func (a *AdminClient) registryFallbackConfig(ctx context.Context, authority string, failed []struct{ NodePath, Entry, Description string }, debug bool) ([]ConfigEntry, error) {
	// Strip host\ prefix from authority to get bare CA name.
	caName := authority
	if idx := strings.LastIndex(caName, "\\"); idx >= 0 {
		caName = caName[idx+1:]
	}

	// Connect to winreg via SMB named pipe.
	pipeAddr := fmt.Sprintf("ncacn_np:%s[\\pipe\\winreg]", a.server)
	if debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] RRP: connecting to %s\n", pipeAddr)
	}

	ctx = gssapi.NewSecurityContext(ctx)

	cc, err := dcerpc.Dial(ctx, pipeAddr,
		dcerpc.WithSeal(),
		dcerpc.WithTargetName(a.server))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to winreg: %w", err)
	}
	defer cc.Close(ctx)

	wrClient, err := winreg.NewWinregClient(ctx, cc,
		dcerpc.WithSeal(),
		dcerpc.WithTargetName(a.server))
	if err != nil {
		return nil, fmt.Errorf("failed to create winreg client: %w", err)
	}

	// Open HKLM
	hlmResp, err := wrClient.OpenLocalMachine(ctx, &winreg.OpenLocalMachineRequest{
		DesiredAccess: winreg.KeyQueryValue | winreg.KeyEnumerateSubKeys,
	})
	if err != nil {
		return nil, fmt.Errorf("OpenLocalMachine failed: %w", err)
	}
	if hlmResp.Return != 0 {
		return nil, fmt.Errorf("OpenLocalMachine returned error: %d", hlmResp.Return)
	}
	hlmKey := hlmResp.Key
	defer wrClient.BaseRegCloseKey(ctx, &winreg.BaseRegCloseKeyRequest{Key: hlmKey}) //nolint:errcheck

	// Open the CA config base key
	caRegPath := fmt.Sprintf("SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\%s", caName)
	if debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] RRP: opening key %s\n", caRegPath)
	}

	caKeyResp, err := wrClient.BaseRegOpenKey(ctx, &winreg.BaseRegOpenKeyRequest{
		Key:           hlmKey,
		SubKey:        rrpStr(caRegPath),
		DesiredAccess: winreg.KeyQueryValue | winreg.KeyEnumerateSubKeys,
	})
	if err != nil {
		return nil, fmt.Errorf("BaseRegOpenKey(%s) failed: %w", caRegPath, err)
	}
	if caKeyResp.Return != 0 {
		return nil, fmt.Errorf("BaseRegOpenKey(%s) returned error: %d", caRegPath, caKeyResp.Return)
	}
	caKey := caKeyResp.ResultKey
	defer wrClient.BaseRegCloseKey(ctx, &winreg.BaseRegCloseKeyRequest{Key: caKey}) //nolint:errcheck

	// Map CSRA NodePath\Entry → registry subkey\valuename
	// CSRA uses:  NodePath="Policy", Entry="EditFlags"
	// Registry:   CA-key\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\EditFlags
	registryMap := map[string]struct {
		subKey    string
		valueName string
	}{
		"Policy\\EditFlags":          {"PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy", "EditFlags"},
		"Policy\\RequestDisposition": {"PolicyModules\\CertificateAuthority_MicrosoftDefault.Policy", "RequestDisposition"},
		"\\InterfaceFlags":           {"", "InterfaceFlags"},
	}

	var entries []ConfigEntry

	for _, f := range failed {
		lookupKey := f.NodePath + "\\" + f.Entry
		regInfo, ok := registryMap[lookupKey]
		if !ok {
			if debug {
				fmt.Fprintf(os.Stderr, "[DEBUG] RRP: no registry mapping for %s\n", lookupKey)
			}
			continue
		}

		// Determine which key to query — subkey of caKey, or caKey itself.
		queryKey := caKey
		if regInfo.subKey != "" {
			subResp, err := wrClient.BaseRegOpenKey(ctx, &winreg.BaseRegOpenKeyRequest{
				Key:           caKey,
				SubKey:        rrpStr(regInfo.subKey),
				DesiredAccess: winreg.KeyQueryValue | winreg.KeyEnumerateSubKeys,
			})
			if err != nil {
				if debug {
					fmt.Fprintf(os.Stderr, "[DEBUG] RRP: failed to open subkey %s: %v\n", regInfo.subKey, err)
				}
				continue
			}
			if subResp.Return != 0 {
				if debug {
					fmt.Fprintf(os.Stderr, "[DEBUG] RRP: open subkey %s returned %d\n", regInfo.subKey, subResp.Return)
				}
				continue
			}
			queryKey = subResp.ResultKey
			defer wrClient.BaseRegCloseKey(ctx, &winreg.BaseRegCloseKeyRequest{Key: queryKey}) //nolint:errcheck
		}

		// Query the DWORD value
		bufSize := uint32(4) // DWORD = 4 bytes
		qvResp, err := wrClient.BaseRegQueryValue(ctx, &winreg.BaseRegQueryValueRequest{
			Key:        queryKey,
			ValueName:  rrpStr(regInfo.valueName),
			Data:       make([]byte, bufSize),
			DataLength: bufSize,
			Length:     bufSize,
		})
		if err != nil {
			if debug {
				fmt.Fprintf(os.Stderr, "[DEBUG] RRP: QueryValue(%s) failed: %v\n", regInfo.valueName, err)
			}
			continue
		}
		if qvResp.Return != 0 {
			if debug {
				fmt.Fprintf(os.Stderr, "[DEBUG] RRP: QueryValue(%s) returned %d\n", regInfo.valueName, qvResp.Return)
			}
			continue
		}

		// Parse DWORD (REG_DWORD = type 4)
		var value interface{}
		if len(qvResp.Data) >= 4 {
			value = int32(binary.LittleEndian.Uint32(qvResp.Data[:4]))
		}

		if debug {
			fmt.Fprintf(os.Stderr, "[DEBUG] RRP: %s\\%s = %v (via registry)\n", f.NodePath, f.Entry, value)
		}

		entries = append(entries, ConfigEntry{
			NodePath: f.NodePath,
			Entry:    f.Entry,
			Value:    value,
		})
	}

	return entries, nil
}

// extractVariantValue gets the underlying Go value from a VARIANT union,
// unwrapping BSTR (FlaggedWordBlob) to plain strings and dereferencing pointers.
func extractVariantValue(vu *oaut.Variant_VarUnion) interface{} {
	raw := vu.GetValue()
	if raw == nil {
		return nil
	}

	// Unwrap oaut.String (FlaggedWordBlob) → plain string.
	switch v := raw.(type) {
	case *oaut.String:
		if v != nil {
			return v.Data
		}
		return ""
	case *int32:
		if v != nil {
			return *v
		}
		return int32(0)
	case *uint32:
		if v != nil {
			return *v
		}
		return uint32(0)
	default:
		return raw
	}
}

// Common HRESULT/Win32 error codes returned by CA config operations.
var hresultNames = map[uint32]string{
	0x80070002: "ERROR_FILE_NOT_FOUND (entry not found)",
	0x80070005: "E_ACCESSDENIED",
	0x80070057: "E_INVALIDARG",
	0x800706BA: "RPC_S_SERVER_UNAVAILABLE",
	0x800706D1: "RPC_S_PROCNUM_OUT_OF_RANGE",
	0x80070032: "ERROR_NOT_SUPPORTED",
	0x80004005: "E_FAIL",
	0x80040154: "REGDB_E_CLASSNOTREG",
}

// formatRPCError extracts and formats HRESULT codes from RPC error strings.
func formatRPCError(err error) string {
	s := err.Error()

	// Try to extract a decimal error code (e.g., "error: -2147024894")
	// and convert to hex HRESULT.
	for _, prefix := range []string{"error: ", "error: code: "} {
		if idx := strings.LastIndex(s, prefix); idx >= 0 {
			numStr := strings.TrimSpace(s[idx+len(prefix):])
			var code int64
			if _, scanErr := fmt.Sscanf(numStr, "%d", &code); scanErr == nil {
				hr := uint32(code)
				if name, ok := hresultNames[hr]; ok {
					return fmt.Sprintf("0x%08X %s", hr, name)
				}
				return fmt.Sprintf("HRESULT 0x%08X", hr)
			}
			// Already hex?
			if _, scanErr := fmt.Sscanf(numStr, "0x%x", &code); scanErr == nil {
				hr := uint32(code)
				if name, ok := hresultNames[hr]; ok {
					return fmt.Sprintf("0x%08X %s", hr, name)
				}
				return fmt.Sprintf("HRESULT 0x%08X", hr)
			}
		}
	}

	return s
}

// proxyDialer adapts a proxy.ContextDialer to satisfy dcerpc.Dialer.
type proxyDialer struct {
	dialer proxy.ContextDialer
}

func (p *proxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return p.dialer.DialContext(ctx, network, address)
}

// newProxyDialer creates a dcerpc-compatible dialer from a SOCKS proxy URL.
func newProxyDialer(proxyURL string) (*proxyDialer, error) {
	// Add socks5 scheme if bare host:port.
	if !strings.Contains(proxyURL, "://") {
		proxyURL = "socks5://" + proxyURL
	}

	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", proxyURL, err)
	}

	d, err := proxy.FromURL(parsed, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("failed to create proxy dialer: %w", err)
	}

	ctxDialer, ok := d.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("proxy dialer for %q does not support DialContext", proxyURL)
	}

	return &proxyDialer{dialer: ctxDialer}, nil
}

// GetTemplates returns the list of certificate templates enabled on the CA.
// Templates are returned as alternating name/OID pairs: [name1, oid1, name2, oid2, ...].
func (c *AdminClient) GetTemplates(ctx context.Context, caName string) ([]string, error) {
	blob, err := c.getRawTemplateBlob(ctx, caName)
	if err != nil {
		return nil, err
	}
	if blob == nil || len(blob.Buffer) == 0 {
		return nil, nil
	}

	decoded := decodeUTF16LE(blob.Buffer)
	parts := strings.Split(decoded, "\n")

	// Filter empty strings (trailing newline/null produces them)
	var templates []string
	for _, p := range parts {
		if p != "" {
			templates = append(templates, p)
		}
	}
	return templates, nil
}

// getRawTemplateBlob returns the raw CertTransportBlob from GetCAProperty(CR_PROP_TEMPLATES).
func (c *AdminClient) getRawTemplateBlob(ctx context.Context, caName string) (*csra.CertTransportBlob, error) {
	resp, err := c.adminD2.GetCAProperty(ctx, &icertadmind2.GetCAPropertyRequest{
		This:          &dcom.ORPCThis{Version: c.comVersion},
		Authority:     caName,
		PropertyID:    CR_PROP_TEMPLATES,
		PropertyIndex: 0,
		PropertyType:  PROPTYPE_STRING,
	}, dcom.WithIPID(c.ipidD2))
	if err != nil {
		return nil, fmt.Errorf("GetCAProperty(CR_PROP_TEMPLATES) failed: %w", err)
	}
	return resp.PropertyValue, nil
}

// EnableTemplate adds a certificate template to the CA's enabled template list.
// templateName is the CN and templateOID is the msPKI-Cert-Template-OID of the template.
func (c *AdminClient) EnableTemplate(ctx context.Context, caName, templateName, templateOID string) error {
	blob, err := c.getRawTemplateBlob(ctx, caName)
	if err != nil {
		return fmt.Errorf("failed to get current templates: %w", err)
	}

	// Check if already enabled by decoding for comparison
	if blob != nil && len(blob.Buffer) > 0 {
		decoded := decodeUTF16LE(blob.Buffer)
		parts := strings.Split(decoded, "\n")
		for i := 0; i < len(parts)-1; i += 2 {
			if strings.EqualFold(parts[i], templateName) {
				return fmt.Errorf("template %q is already enabled on the CA", templateName)
			}
		}
	}

	// Encode the new template entry as UTF-16LE: "name\nOID\n"
	entry := templateName + "\n" + templateOID + "\n"
	entryBytes := encodeUTF16LE(entry)
	// Strip the null terminator added by encodeUTF16LE (last 2 bytes)
	entryBytes = entryBytes[:len(entryBytes)-2]

	// Prepend to existing buffer
	var newBuffer []byte
	if blob != nil && len(blob.Buffer) > 0 {
		newBuffer = append(entryBytes, blob.Buffer...)
	} else {
		newBuffer = entryBytes
	}

	return c.setTemplateBlob(ctx, caName, &csra.CertTransportBlob{
		Length: uint32(len(newBuffer)),
		Buffer: newBuffer,
	})
}

// DisableTemplate removes a certificate template from the CA's enabled template list.
func (c *AdminClient) DisableTemplate(ctx context.Context, caName, templateName string) error {
	blob, err := c.getRawTemplateBlob(ctx, caName)
	if err != nil {
		return fmt.Errorf("failed to get current templates: %w", err)
	}

	if blob == nil || len(blob.Buffer) == 0 {
		return fmt.Errorf("template %q is not enabled on the CA (no templates found)", templateName)
	}

	// Find the template in the raw buffer by scanning UTF-16LE newline-separated entries.
	// Format: name1\nOID1\nname2\nOID2\n...
	// We need to find the byte offset of the target "name\nOID\n" pair and remove it.
	decoded := decodeUTF16LE(blob.Buffer)
	parts := strings.Split(decoded, "\n")

	// Find which template pair to remove
	found := false
	charOffset := 0
	removeCharLen := 0
	pos := 0
	for i := 0; i < len(parts)-1; i += 2 {
		entryLen := len([]rune(parts[i])) + 1 + len([]rune(parts[i+1])) + 1 // name + \n + OID + \n
		if strings.EqualFold(parts[i], templateName) {
			found = true
			charOffset = pos
			removeCharLen = entryLen
			break
		}
		pos += entryLen
	}

	if !found {
		return fmt.Errorf("template %q is not enabled on the CA", templateName)
	}

	// Remove the corresponding bytes from the raw buffer (each char = 2 bytes in UTF-16LE)
	byteStart := charOffset * 2
	byteEnd := (charOffset + removeCharLen) * 2
	if byteEnd > len(blob.Buffer) {
		byteEnd = len(blob.Buffer)
	}

	newBuffer := make([]byte, 0, len(blob.Buffer)-byteEnd+byteStart)
	newBuffer = append(newBuffer, blob.Buffer[:byteStart]...)
	newBuffer = append(newBuffer, blob.Buffer[byteEnd:]...)

	return c.setTemplateBlob(ctx, caName, &csra.CertTransportBlob{
		Length: uint32(len(newBuffer)),
		Buffer: newBuffer,
	})
}

// setTemplateBlob writes the template blob back to the CA via SetCAProperty.
func (c *AdminClient) setTemplateBlob(ctx context.Context, caName string, blob *csra.CertTransportBlob) error {
	resp, err := c.adminD2.SetCAProperty(ctx, &icertadmind2.SetCAPropertyRequest{
		This:          &dcom.ORPCThis{Version: c.comVersion},
		Authority:     caName,
		PropertyID:    CR_PROP_TEMPLATES,
		PropertyIndex: 0,
		PropertyType:  PROPTYPE_STRING,
		PropertyValue: blob,
	}, dcom.WithIPID(c.ipidD2))
	if err != nil {
		return fmt.Errorf("SetCAProperty(CR_PROP_TEMPLATES) failed: %w", err)
	}

	if resp.Return != 0 {
		hr := uint32(resp.Return)
		if name, ok := hresultNames[hr]; ok {
			return fmt.Errorf("SetCAProperty failed: 0x%08X %s", hr, name)
		}
		return fmt.Errorf("SetCAProperty failed: HRESULT 0x%08X", hr)
	}

	return nil
}

// decodeUTF16LE decodes a byte slice of UTF-16LE data to a Go string.
func decodeUTF16LE(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	// Trim null terminators
	for len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	return string(utf16.Decode(u16))
}
