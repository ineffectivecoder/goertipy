package adcs

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iactivation/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dcom/iobjectexporter/v0"

	"github.com/oiweiwei/go-msrpc/msrpc/dcom/csra"
	csra_client "github.com/oiweiwei/go-msrpc/msrpc/dcom/csra/client"
	icertadmind "github.com/oiweiwei/go-msrpc/msrpc/dcom/csra/icertadmind/v0"
	icertadmind2 "github.com/oiweiwei/go-msrpc/msrpc/dcom/csra/icertadmind2/v0"
	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	"github.com/oiweiwei/go-msrpc/msrpc/erref/hresult"
	"github.com/oiweiwei/go-msrpc/ssp"
	"github.com/oiweiwei/go-msrpc/ssp/credential"
	"github.com/oiweiwei/go-msrpc/ssp/gssapi"
)

// CertAdminClassID is the CLSID for the CertAdmin DCOM class (MS-CSRA §1.9).
// ICertAdminD IID is d99e6e71-..., CLSID is d99e6e73-... (per Certipy/MS-CSRA).
var CertAdminClassID = &dcom.ClassID{Data1: 0xd99e6e73, Data2: 0xfc88, Data3: 0x11d0,
	Data4: []byte{0xb4, 0x98, 0x00, 0xa0, 0xc9, 0x03, 0x12, 0xf3}}

// AdminClient wraps the ICertAdminD/D2 DCOM interfaces for CA administration.
// Uses proper DCOM activation via RemoteActivation on port 135 + OXID bindings.
type AdminClient struct {
	client     csra_client.Client
	remoteIPID *dcom.IPID
	conns      []dcerpc.Conn
}

// AdminOptions holds connection options for the admin client.
type AdminOptions struct {
	Server   string
	Username string
	Password string
	NTHash   string
	Domain   string
	ProxyURL string // SOCKS5 proxy URL (reserved for future use)
	Debug    bool
}

// ConnectAdmin establishes a DCOM connection to the CA's ICertAdminD/D2
// interfaces using proper DCOM object activation (RemoteActivation).
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

	clientOpts := []dcerpc.Option{
		dcerpc.WithSeal(),
		dcerpc.WithTargetName(opts.Server),
	}

	admin := &AdminClient{}

	// Step 1: Dial port 135 (OX resolver well-known endpoint).
	if opts.Debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] Connecting to OX resolver on %s:135\n", opts.Server)
	}
	cc, err := dcerpc.Dial(ctx, net.JoinHostPort(opts.Server, "135"), clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to OX resolver on %s: %w", opts.Server, err)
	}
	admin.conns = append(admin.conns, cc)

	// Step 2: ObjectExporter — get COM version via ServerAlive2.
	if opts.Debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] Querying ServerAlive2 for COM version\n")
	}
	oxCli, err := iobjectexporter.NewObjectExporterClient(ctx, cc, clientOpts...)
	if err != nil {
		admin.Close()
		return nil, fmt.Errorf("failed to create ObjectExporter client: %w", err)
	}

	srv, err := oxCli.ServerAlive2(ctx, &iobjectexporter.ServerAlive2Request{})
	if err != nil {
		admin.Close()
		return nil, fmt.Errorf("ServerAlive2 failed: %w", err)
	}

	if opts.Debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] COM version: %d.%d\n",
			srv.COMVersion.MajorVersion, srv.COMVersion.MinorVersion)
	}

	// Step 3: RemoteActivation — activate the CertAdmin DCOM object.
	if opts.Debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] Activating CertAdmin DCOM object (CLSID: %v)\n",
			CertAdminClassID.GUID())
	}
	actCli, err := iactivation.NewActivationClient(ctx, cc, clientOpts...)
	if err != nil {
		admin.Close()
		return nil, fmt.Errorf("failed to create Activation client: %w", err)
	}

	act, err := actCli.RemoteActivation(ctx, &iactivation.RemoteActivationRequest{
		ORPCThis: &dcom.ORPCThis{Version: srv.COMVersion},
		ClassID:  CertAdminClassID.GUID(),
		IIDs:     []*dcom.IID{icertadmind2.CertAdminD2IID},
		// Protocol sequence 7 = ncacn_ip_tcp (TCP/IP).
		RequestedProtocolSequences: []uint16{7},
	})
	if err != nil {
		admin.Close()
		return nil, fmt.Errorf("RemoteActivation failed: %w", err)
	}

	if act.HResult != 0 {
		admin.Close()
		return nil, fmt.Errorf("RemoteActivation HRESULT error: %s", hresult.FromCode(uint32(act.HResult)))
	}

	if opts.Debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] DCOM activation successful, IPID: %v\n",
			act.InterfaceData[0].IPID())
		fmt.Fprintf(os.Stderr, "[DEBUG] RemoteUnknown IPID: %v\n", act.RemoteUnknown)
	}

	// Step 4: Dial the OXID bindings (dynamic port returned by activation).
	wcc, err := dcerpc.Dial(ctx, opts.Server,
		append(clientOpts, act.OXIDBindings.EndpointsByProtocol("ncacn_ip_tcp")...)...)
	if err != nil {
		admin.Close()
		return nil, fmt.Errorf("failed to connect to OXID binding: %w", err)
	}
	admin.conns = append(admin.conns, wcc)

	// Step 5: Create the CSRA client set (ICertAdminD + ICertAdminD2).
	ctx = gssapi.NewSecurityContext(ctx)

	client, err := csra_client.NewClient(ctx, wcc,
		append(clientOpts, dcom.WithIPID(act.InterfaceData[0].IPID()))...)
	if err != nil {
		admin.Close()
		return nil, fmt.Errorf("failed to create CSRA client: %w", err)
	}
	admin.client = client
	admin.remoteIPID = act.InterfaceData[0].IPID()

	if opts.Debug {
		fmt.Fprintf(os.Stderr, "[DEBUG] CSRA client created successfully\n")
	}

	return admin, nil
}

// Close releases all admin client connections.
func (a *AdminClient) Close() {
	for _, cc := range a.conns {
		cc.Close(context.Background())
	}
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

	_, err := a.client.CertAdminD().RevokeCertificate(ctx, &icertadmind.RevokeCertificateRequest{
		This:         &dcom.ORPCThis{Version: &dcom.COMVersion{MajorVersion: 5, MinorVersion: 7}},
		Authority:    authority,
		SerialNumber: serial,
		Reason:       opts.Reason,
		FileTime:     ft,
	})
	if err != nil {
		return fmt.Errorf("RevokeCertificate RPC failed: %w", err)
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
// NOTE: Only scalar-typed entries (int/string) are listed here.
// Array-typed entries (CRLPublicationURLs, CACertPublicationURLs,
// EnableRequestExtensionList, DisableExtensionList) are excluded because
// go-msrpc's VARIANT unmarshaler panics on SafeArray responses.
// Use RRP (Remote Registry Protocol) for those entries instead.
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

	resp, err := a.client.CertAdminD2().GetConfigEntry(ctx, &icertadmind2.GetConfigEntryRequest{
		This:      &dcom.ORPCThis{Version: &dcom.COMVersion{MajorVersion: 5, MinorVersion: 7}},
		Authority: authority,
		NodePath:  nodePath,
		Entry:     entry,
	})
	if err != nil {
		return nil, fmt.Errorf("GetConfigEntry(%s\\%s) failed: %w", nodePath, entry, err)
	}

	// Extract value from VARIANT.
	var value interface{}
	if resp.Variant != nil && resp.Variant.VarUnion != nil {
		value = resp.Variant.VarUnion.GetValue()
	}

	return &ConfigEntry{
		NodePath: nodePath,
		Entry:    entry,
		Value:    value,
	}, nil
}

// DumpConfig retrieves all known configuration entries from the CA.
// Entries that fail (e.g., not found) are skipped with a warning to stderr.
func (a *AdminClient) DumpConfig(ctx context.Context, authority string, debug bool) ([]ConfigEntry, error) {
	var entries []ConfigEntry

	for _, known := range knownConfigEntries {
		entry, err := a.GetConfigEntry(ctx, authority, known.NodePath, known.Entry)
		if err != nil {
			if debug {
				fmt.Fprintf(os.Stderr, "[DEBUG] Skipping %s\\%s: %v\n", known.NodePath, known.Entry, err)
			}
			continue
		}
		entries = append(entries, *entry)
	}

	return entries, nil
}

// Template management constants (MS-WCCE §3.2.1.4.3.2).
const (
	crPropTemplates int32 = 0x1d // CR_PROP_TEMPLATES
	propTypeString  int32 = 4    // PROPTYPE_STRING
)

// decodeUTF16LE decodes a UTF-16LE byte slice to a Go string.
func decodeUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	// Trim null terminator if present.
	if len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	return string(utf16.Decode(u16))
}

// GetTemplates retrieves the list of enabled certificate templates from the CA.
// Returns a slice of strings alternating between template name and OID:
// [name1, oid1, name2, oid2, ...]
func (a *AdminClient) GetTemplates(ctx context.Context, authority string) ([]string, error) {
	if idx := strings.LastIndex(authority, "\\"); idx >= 0 {
		authority = authority[idx+1:]
	}

	resp, err := a.client.CertAdminD2().GetCAProperty(ctx, &icertadmind2.GetCAPropertyRequest{
		This:          &dcom.ORPCThis{Version: &dcom.COMVersion{MajorVersion: 5, MinorVersion: 7}},
		Authority:     authority,
		PropertyID:    crPropTemplates,
		PropertyIndex: 0,
		PropertyType:  propTypeString,
	})
	if err != nil {
		return nil, fmt.Errorf("GetCAProperty(CR_PROP_TEMPLATES) failed: %w", err)
	}

	if resp.PropertyValue == nil || len(resp.PropertyValue.Buffer) == 0 {
		return nil, nil
	}

	// The blob is UTF-16LE encoded "name\nOID\nname\nOID\n..."
	raw := decodeUTF16LE(resp.PropertyValue.Buffer)
	lines := strings.Split(strings.TrimRight(raw, "\n"), "\n")

	// Filter out empty strings.
	var result []string
	for _, l := range lines {
		if l != "" {
			result = append(result, l)
		}
	}
	return result, nil
}

// EnableTemplate enables a certificate template on the CA by adding it to the
// CR_PROP_TEMPLATES list. Requires ManageCA rights.
func (a *AdminClient) EnableTemplate(ctx context.Context, authority, templateName, templateOID string) error {
	if idx := strings.LastIndex(authority, "\\"); idx >= 0 {
		authority = authority[idx+1:]
	}

	// Get current templates.
	existing, err := a.GetTemplates(ctx, authority)
	if err != nil {
		return fmt.Errorf("failed to get current templates: %w", err)
	}

	// Check if already enabled.
	for i := 0; i < len(existing)-1; i += 2 {
		if strings.EqualFold(existing[i], templateName) {
			return fmt.Errorf("template %q is already enabled", templateName)
		}
	}

	// Build new blob: prepend new template entry.
	newEntry := templateName + "\n" + templateOID + "\n"
	var existing_str string
	for _, s := range existing {
		existing_str += s + "\n"
	}
	fullStr := newEntry + existing_str
	blob := encodeUTF16LE(fullStr)

	_, err = a.client.CertAdminD2().SetCAProperty(ctx, &icertadmind2.SetCAPropertyRequest{
		This:          &dcom.ORPCThis{Version: &dcom.COMVersion{MajorVersion: 5, MinorVersion: 7}},
		Authority:     authority,
		PropertyID:    crPropTemplates,
		PropertyIndex: 0,
		PropertyType:  propTypeString,
		PropertyValue: &csra.CertTransportBlob{
			Length: uint32(len(blob)),
			Buffer: blob,
		},
	})
	if err != nil {
		return fmt.Errorf("SetCAProperty(CR_PROP_TEMPLATES) failed: %w", err)
	}

	return nil
}

// DisableTemplate disables a certificate template on the CA by removing it from
// the CR_PROP_TEMPLATES list. Requires ManageCA rights.
func (a *AdminClient) DisableTemplate(ctx context.Context, authority, templateName string) error {
	if idx := strings.LastIndex(authority, "\\"); idx >= 0 {
		authority = authority[idx+1:]
	}

	// Get current templates.
	existing, err := a.GetTemplates(ctx, authority)
	if err != nil {
		return fmt.Errorf("failed to get current templates: %w", err)
	}

	// Find and remove the template (name+OID pair).
	found := false
	var filtered []string
	for i := 0; i < len(existing)-1; i += 2 {
		if strings.EqualFold(existing[i], templateName) {
			found = true
			continue // Skip this pair.
		}
		filtered = append(filtered, existing[i], existing[i+1])
	}
	// Handle odd trailing element.
	if len(existing)%2 == 1 {
		filtered = append(filtered, existing[len(existing)-1])
	}

	if !found {
		return fmt.Errorf("template %q not found in enabled templates", templateName)
	}

	// Build new blob.
	var newStr string
	for _, s := range filtered {
		newStr += s + "\n"
	}
	blob := encodeUTF16LE(newStr)

	_, err = a.client.CertAdminD2().SetCAProperty(ctx, &icertadmind2.SetCAPropertyRequest{
		This:          &dcom.ORPCThis{Version: &dcom.COMVersion{MajorVersion: 5, MinorVersion: 7}},
		Authority:     authority,
		PropertyID:    crPropTemplates,
		PropertyIndex: 0,
		PropertyType:  propTypeString,
		PropertyValue: &csra.CertTransportBlob{
			Length: uint32(len(blob)),
			Buffer: blob,
		},
	})
	if err != nil {
		return fmt.Errorf("SetCAProperty(CR_PROP_TEMPLATES) failed: %w", err)
	}

	return nil
}
