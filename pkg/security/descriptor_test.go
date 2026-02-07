package security

import (
	"encoding/binary"
	"testing"
)

func TestSIDString(t *testing.T) {
	tests := []struct {
		name string
		sid  *SID
		want string
	}{
		{
			name: "Everyone",
			sid: &SID{
				Revision:            1,
				SubAuthorityCount:   1,
				IdentifierAuthority: [6]byte{0, 0, 0, 0, 0, 1},
				SubAuthorities:      []uint32{0},
			},
			want: "S-1-1-0",
		},
		{
			name: "Local System",
			sid: &SID{
				Revision:            1,
				SubAuthorityCount:   1,
				IdentifierAuthority: [6]byte{0, 0, 0, 0, 0, 5},
				SubAuthorities:      []uint32{18},
			},
			want: "S-1-5-18",
		},
		{
			name: "Domain Users (RID 513)",
			sid: &SID{
				Revision:            1,
				SubAuthorityCount:   5,
				IdentifierAuthority: [6]byte{0, 0, 0, 0, 0, 5},
				SubAuthorities:      []uint32{21, 1234567890, 987654321, 111111111, 513},
			},
			want: "S-1-5-21-1234567890-987654321-111111111-513",
		},
		{
			name: "nil SID",
			sid:  nil,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.sid.String()
			if got != tt.want {
				t.Errorf("SID.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSIDGetRID(t *testing.T) {
	sid := &SID{
		Revision:            1,
		SubAuthorityCount:   2,
		IdentifierAuthority: [6]byte{0, 0, 0, 0, 0, 5},
		SubAuthorities:      []uint32{21, 512},
	}
	if got := sid.GetRID(); got != 512 {
		t.Errorf("GetRID() = %d, want 512", got)
	}

	// Nil SID
	var nilSID *SID
	if got := nilSID.GetRID(); got != 0 {
		t.Errorf("nil GetRID() = %d, want 0", got)
	}
}

func TestSIDWellKnown(t *testing.T) {
	sid := &SID{
		Revision:            1,
		SubAuthorityCount:   1,
		IdentifierAuthority: [6]byte{0, 0, 0, 0, 0, 5},
		SubAuthorities:      []uint32{11},
	}
	name, ok := sid.IsWellKnown()
	if !ok || name != "Authenticated Users" {
		t.Errorf("IsWellKnown() = %q, %v, want \"Authenticated Users\", true", name, ok)
	}
}

func TestGUIDString(t *testing.T) {
	g := &GUID{
		Data1: 0x0e10c968,
		Data2: 0x78fb,
		Data3: 0x11d2,
		Data4: [8]byte{0x90, 0xd4, 0x00, 0xc0, 0x4f, 0x79, 0xdc, 0x55},
	}
	want := "0e10c968-78fb-11d2-90d4-00c04f79dc55"
	if got := g.String(); got != want {
		t.Errorf("GUID.String() = %q, want %q", got, want)
	}

	// Nil GUID
	var nilGUID *GUID
	if got := nilGUID.String(); got != "" {
		t.Errorf("nil GUID.String() = %q, want empty", got)
	}
}

func TestGUIDEquals(t *testing.T) {
	g1 := &GUID_ENROLL
	g2 := &GUID{0x0e10c968, 0x78fb, 0x11d2, [8]byte{0x90, 0xd4, 0x00, 0xc0, 0x4f, 0x79, 0xdc, 0x55}}
	if !g1.Equals(g2) {
		t.Error("GUID_ENROLL should equal identical GUID")
	}

	g3 := &GUID_AUTOENROLL
	if g1.Equals(g3) {
		t.Error("GUID_ENROLL should not equal GUID_AUTOENROLL")
	}

	// nil checks
	if g1.Equals(nil) {
		t.Error("non-nil GUID.Equals(nil) should be false")
	}
	var nilGUID *GUID
	if nilGUID.Equals(g1) {
		t.Error("nil.Equals(non-nil) should be false")
	}
}

// buildSecurityDescriptor creates a minimal valid binary security descriptor for tests
func buildSecurityDescriptor(ownerSID *SID, dacl *ACL) []byte {
	// Header: 20 bytes
	// Revision(1) + Sbz1(1) + Control(2) + OwnerOffset(4) + GroupOffset(4) + SACLOffset(4) + DACLOffset(4)
	buf := make([]byte, 0, 256)

	// Header
	buf = append(buf, 1)    // Revision
	buf = append(buf, 0)    // Sbz1
	buf = append(buf, 0, 0) // Control (little-endian)

	ownerOffset := uint32(20)
	groupOffset := uint32(0)
	saclOffset := uint32(0)

	// Build owner SID bytes
	ownerBytes := encodeSID(ownerSID)

	// DACL comes after owner SID
	daclOffset := uint32(0)
	var daclBytes []byte
	if dacl != nil {
		daclOffset = ownerOffset + uint32(len(ownerBytes))
		daclBytes = encodeACL(dacl)
	}

	// Write offsets
	buf = binary.LittleEndian.AppendUint32(buf, ownerOffset)
	buf = binary.LittleEndian.AppendUint32(buf, groupOffset)
	buf = binary.LittleEndian.AppendUint32(buf, saclOffset)
	buf = binary.LittleEndian.AppendUint32(buf, daclOffset)

	buf = append(buf, ownerBytes...)
	buf = append(buf, daclBytes...)

	return buf
}

func encodeSID(s *SID) []byte {
	if s == nil {
		return nil
	}
	buf := make([]byte, 8+len(s.SubAuthorities)*4)
	buf[0] = s.Revision
	buf[1] = byte(len(s.SubAuthorities))
	copy(buf[2:8], s.IdentifierAuthority[:])
	for i, sa := range s.SubAuthorities {
		binary.LittleEndian.PutUint32(buf[8+i*4:], sa)
	}
	return buf
}

func encodeACL(acl *ACL) []byte {
	if acl == nil {
		return nil
	}
	// Simple ACL encoding: header (8 bytes) + ACE entries
	header := make([]byte, 8)
	header[0] = acl.Revision
	binary.LittleEndian.PutUint16(header[4:6], uint16(len(acl.Entries)))

	aceBytes := make([]byte, 0)
	for _, ace := range acl.Entries {
		aceData := encodeACE(ace)
		aceBytes = append(aceBytes, aceData...)
	}

	totalSize := 8 + len(aceBytes)
	binary.LittleEndian.PutUint16(header[2:4], uint16(totalSize))
	return append(header, aceBytes...)
}

func encodeACE(ace *ACE) []byte {
	sidBytes := encodeSID(ace.SID)
	size := 8 + len(sidBytes)

	buf := make([]byte, size)
	buf[0] = ace.Type
	buf[1] = ace.Flags
	binary.LittleEndian.PutUint16(buf[2:4], uint16(size))
	binary.LittleEndian.PutUint32(buf[4:8], ace.AccessMask)
	copy(buf[8:], sidBytes)
	return buf
}

func TestParseSecurityDescriptor(t *testing.T) {
	ownerSID := &SID{
		Revision:            1,
		SubAuthorityCount:   1,
		IdentifierAuthority: [6]byte{0, 0, 0, 0, 0, 5},
		SubAuthorities:      []uint32{18},
	}

	data := buildSecurityDescriptor(ownerSID, nil)
	sd, err := ParseSecurityDescriptor(data)
	if err != nil {
		t.Fatalf("ParseSecurityDescriptor() error: %v", err)
	}
	if sd.OwnerSID == nil {
		t.Fatal("expected owner SID to be parsed")
	}
	if got := sd.OwnerSID.String(); got != "S-1-5-18" {
		t.Errorf("owner SID = %q, want S-1-5-18", got)
	}
}

func TestParseSecurityDescriptorTooShort(t *testing.T) {
	_, err := ParseSecurityDescriptor([]byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for short descriptor")
	}
}

func TestHasDangerousPermissions(t *testing.T) {
	tests := []struct {
		name      string
		perms     *TemplatePermissions
		dangerous bool
	}{
		{
			name: "Domain Users with full control",
			perms: &TemplatePermissions{
				FullControlPrincipals: []string{"CORP\\Domain Users"},
			},
			dangerous: true,
		},
		{
			name: "Authenticated Users with write property",
			perms: &TemplatePermissions{
				WritePropertyPrincipals: []string{"Authenticated Users"},
			},
			dangerous: true,
		},
		{
			name: "Domain Admins only",
			perms: &TemplatePermissions{
				FullControlPrincipals: []string{"CORP\\Domain Admins"},
			},
			dangerous: false,
		},
		{
			name: "Everyone with write owner",
			perms: &TemplatePermissions{
				WriteOwnerPrincipals: []string{"Everyone"},
			},
			dangerous: true,
		},
		{
			name:      "no dangerous perms",
			perms:     &TemplatePermissions{},
			dangerous: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.perms.HasDangerousPermissions(); got != tt.dangerous {
				t.Errorf("HasDangerousPermissions() = %v, want %v", got, tt.dangerous)
			}
		})
	}
}

func TestIsLowPrivilegeGroupCaseInsensitive(t *testing.T) {
	tests := []struct {
		principal string
		expect    bool
	}{
		{"Domain Users", true},
		{"domain users", true},
		{"CORP\\Domain Users", true},
		{"corp\\domain users", true},
		{"CORP\\DOMAIN USERS", true},
		{"Everyone", true},
		{"Domain Admins", false},
		{"SomeUser", false},
		{"CORP\\Authenticated Users", true},
	}
	for _, tt := range tests {
		t.Run(tt.principal, func(t *testing.T) {
			if got := isLowPrivilegeGroup(tt.principal); got != tt.expect {
				t.Errorf("isLowPrivilegeGroup(%q) = %v, want %v", tt.principal, got, tt.expect)
			}
		})
	}
}

func TestAppendUnique(t *testing.T) {
	s := []string{"a", "b"}
	s = appendUnique(s, "b") // duplicate
	if len(s) != 2 {
		t.Errorf("appendUnique should not add duplicate, got len=%d", len(s))
	}
	s = appendUnique(s, "c")
	if len(s) != 3 {
		t.Errorf("appendUnique should add new item, got len=%d", len(s))
	}
}
