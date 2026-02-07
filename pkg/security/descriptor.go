package security

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// SecurityDescriptor represents a Windows security descriptor
type SecurityDescriptor struct {
	Revision byte
	Sbz1     byte
	Control  uint16
	OwnerSID *SID
	GroupSID *SID
	SACL     *ACL
	DACL     *ACL
}

// ACL represents an Access Control List
type ACL struct {
	Revision byte
	Sbz1     byte
	Size     uint16
	Count    uint16
	Sbz2     uint16
	Entries  []*ACE
}

// ACE represents an Access Control Entry
type ACE struct {
	Type                byte
	Flags               byte
	Size                uint16
	AccessMask          uint32
	SID                 *SID
	ObjectType          *GUID // For object ACEs
	InheritedObjectType *GUID // For object ACEs
}

// SID represents a Windows Security Identifier
type SID struct {
	Revision            byte
	SubAuthorityCount   byte
	IdentifierAuthority [6]byte
	SubAuthorities      []uint32
}

// GUID represents a Windows GUID
type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// ACE Types
const (
	ACCESS_ALLOWED_ACE_TYPE        = 0x00
	ACCESS_DENIED_ACE_TYPE         = 0x01
	ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05
	ACCESS_DENIED_OBJECT_ACE_TYPE  = 0x06
)

// Access mask flags for AD objects
const (
	ADS_RIGHT_DELETE            = 0x00010000
	ADS_RIGHT_READ_CONTROL      = 0x00020000
	ADS_RIGHT_WRITE_DAC         = 0x00040000
	ADS_RIGHT_WRITE_OWNER       = 0x00080000
	ADS_RIGHT_DS_CREATE_CHILD   = 0x00000001
	ADS_RIGHT_DS_DELETE_CHILD   = 0x00000002
	ADS_RIGHT_ACTRL_DS_LIST     = 0x00000004
	ADS_RIGHT_DS_SELF           = 0x00000008
	ADS_RIGHT_DS_READ_PROP      = 0x00000010
	ADS_RIGHT_DS_WRITE_PROP     = 0x00000020
	ADS_RIGHT_DS_DELETE_TREE    = 0x00000040
	ADS_RIGHT_DS_LIST_OBJECT    = 0x00000080
	ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
	ADS_RIGHT_GENERIC_ALL       = 0x10000000
	ADS_RIGHT_GENERIC_EXECUTE   = 0x20000000
	ADS_RIGHT_GENERIC_WRITE     = 0x40000000
	ADS_RIGHT_GENERIC_READ      = 0x80000000
)

// Certificate template extended rights GUIDs
var (
	// Certificate-Enrollment extended right
	GUID_ENROLL = GUID{0x0e10c968, 0x78fb, 0x11d2, [8]byte{0x90, 0xd4, 0x00, 0xc0, 0x4f, 0x79, 0xdc, 0x55}}
	// Certificate-AutoEnrollment extended right
	GUID_AUTOENROLL = GUID{0xa05b8cc2, 0x17bc, 0x4802, [8]byte{0xa7, 0x10, 0xe7, 0xc1, 0x5a, 0xb8, 0x66, 0xa2}}
)

// Well-known SID prefixes
var wellKnownSIDs = map[string]string{
	"S-1-0-0":  "Null SID",
	"S-1-1-0":  "Everyone",
	"S-1-2-0":  "Local",
	"S-1-3-0":  "Creator Owner",
	"S-1-3-1":  "Creator Group",
	"S-1-5-1":  "Dialup",
	"S-1-5-2":  "Network",
	"S-1-5-3":  "Batch",
	"S-1-5-4":  "Interactive",
	"S-1-5-6":  "Service",
	"S-1-5-7":  "Anonymous",
	"S-1-5-9":  "Enterprise Domain Controllers",
	"S-1-5-10": "Self",
	"S-1-5-11": "Authenticated Users",
	"S-1-5-18": "Local System",
	"S-1-5-19": "Local Service",
	"S-1-5-20": "Network Service",
}

// Well-known domain RIDs
var wellKnownRIDs = map[uint32]string{
	500: "Administrator",
	501: "Guest",
	502: "KRBTGT",
	512: "Domain Admins",
	513: "Domain Users",
	514: "Domain Guests",
	515: "Domain Computers",
	516: "Domain Controllers",
	517: "Cert Publishers",
	518: "Schema Admins",
	519: "Enterprise Admins",
	520: "Group Policy Creator Owners",
	526: "Key Admins",
	527: "Enterprise Key Admins",
	544: "Administrators",
	545: "Users",
	546: "Guests",
}

// ParseSecurityDescriptor parses a binary security descriptor
func ParseSecurityDescriptor(data []byte) (*SecurityDescriptor, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("security descriptor too short: %d bytes", len(data))
	}

	reader := bytes.NewReader(data)
	sd := &SecurityDescriptor{}

	// Read header — check each read for errors
	if err := binary.Read(reader, binary.LittleEndian, &sd.Revision); err != nil {
		return nil, fmt.Errorf("reading revision: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &sd.Sbz1); err != nil {
		return nil, fmt.Errorf("reading sbz1: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &sd.Control); err != nil {
		return nil, fmt.Errorf("reading control: %w", err)
	}

	var ownerOffset, groupOffset, saclOffset, daclOffset uint32
	if err := binary.Read(reader, binary.LittleEndian, &ownerOffset); err != nil {
		return nil, fmt.Errorf("reading owner offset: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &groupOffset); err != nil {
		return nil, fmt.Errorf("reading group offset: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &saclOffset); err != nil {
		return nil, fmt.Errorf("reading SACL offset: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &daclOffset); err != nil {
		return nil, fmt.Errorf("reading DACL offset: %w", err)
	}

	// Parse Owner SID
	if ownerOffset > 0 && int(ownerOffset) < len(data) {
		sd.OwnerSID, _ = parseSID(data[ownerOffset:])
	}

	// Parse Group SID
	if groupOffset > 0 && int(groupOffset) < len(data) {
		sd.GroupSID, _ = parseSID(data[groupOffset:])
	}

	// Parse DACL
	if daclOffset > 0 && int(daclOffset) < len(data) {
		sd.DACL, _ = parseACL(data[daclOffset:])
	}

	return sd, nil
}

func parseSID(data []byte) (*SID, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("SID too short: %d bytes", len(data))
	}

	sid := &SID{
		Revision:          data[0],
		SubAuthorityCount: data[1],
	}
	copy(sid.IdentifierAuthority[:], data[2:8])

	expectedLen := 8 + int(sid.SubAuthorityCount)*4
	if len(data) < expectedLen {
		return nil, fmt.Errorf("SID data too short: need %d, have %d", expectedLen, len(data))
	}

	sid.SubAuthorities = make([]uint32, sid.SubAuthorityCount)
	reader := bytes.NewReader(data[8:])
	for i := 0; i < int(sid.SubAuthorityCount); i++ {
		if err := binary.Read(reader, binary.LittleEndian, &sid.SubAuthorities[i]); err != nil {
			return nil, fmt.Errorf("reading sub-authority %d: %w", i, err)
		}
	}

	return sid, nil
}

func parseACL(data []byte) (*ACL, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("ACL too short: %d bytes", len(data))
	}

	reader := bytes.NewReader(data)
	acl := &ACL{}

	if err := binary.Read(reader, binary.LittleEndian, &acl.Revision); err != nil {
		return nil, fmt.Errorf("reading ACL revision: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &acl.Sbz1); err != nil {
		return nil, fmt.Errorf("reading ACL sbz1: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &acl.Size); err != nil {
		return nil, fmt.Errorf("reading ACL size: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &acl.Count); err != nil {
		return nil, fmt.Errorf("reading ACL count: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &acl.Sbz2); err != nil {
		return nil, fmt.Errorf("reading ACL sbz2: %w", err)
	}

	// Parse ACEs
	offset := 8
	for i := 0; i < int(acl.Count) && offset < len(data); i++ {
		if offset+4 > len(data) {
			break // Not enough data for ACE header
		}
		ace, aceSize := parseACE(data[offset:])
		if ace != nil {
			acl.Entries = append(acl.Entries, ace)
		}
		if aceSize == 0 {
			break
		}
		offset += aceSize
	}

	return acl, nil
}

func parseACE(data []byte) (*ACE, int) {
	if len(data) < 8 {
		return nil, 0
	}

	ace := &ACE{
		Type:  data[0],
		Flags: data[1],
	}
	ace.Size = binary.LittleEndian.Uint16(data[2:4])
	ace.AccessMask = binary.LittleEndian.Uint32(data[4:8])

	if int(ace.Size) > len(data) || ace.Size < 8 {
		return nil, 0
	}

	// Parse based on ACE type
	sidOffset := 8

	// Object ACE types have additional GUID fields
	if ace.Type == ACCESS_ALLOWED_OBJECT_ACE_TYPE || ace.Type == ACCESS_DENIED_OBJECT_ACE_TYPE {
		if len(data) < 12 {
			return ace, int(ace.Size)
		}
		objectFlags := binary.LittleEndian.Uint32(data[8:12])
		sidOffset = 12

		if objectFlags&0x01 != 0 { // ACE_OBJECT_TYPE_PRESENT
			if len(data) >= sidOffset+16 {
				ace.ObjectType = parseGUID(data[sidOffset:])
				sidOffset += 16
			}
		}
		if objectFlags&0x02 != 0 { // ACE_INHERITED_OBJECT_TYPE_PRESENT
			if len(data) >= sidOffset+16 {
				ace.InheritedObjectType = parseGUID(data[sidOffset:])
				sidOffset += 16
			}
		}
	}

	// Parse SID — ensure we don't read past the ACE boundary
	if sidOffset < int(ace.Size) && sidOffset < len(data) {
		remaining := data[sidOffset:]
		if aceEnd := int(ace.Size) - sidOffset; aceEnd > 0 && aceEnd <= len(remaining) {
			remaining = remaining[:aceEnd]
		}
		ace.SID, _ = parseSID(remaining)
	}

	return ace, int(ace.Size)
}

func parseGUID(data []byte) *GUID {
	if len(data) < 16 {
		return nil
	}
	g := &GUID{}
	reader := bytes.NewReader(data[:16])
	if err := binary.Read(reader, binary.LittleEndian, &g.Data1); err != nil {
		return nil
	}
	if err := binary.Read(reader, binary.LittleEndian, &g.Data2); err != nil {
		return nil
	}
	if err := binary.Read(reader, binary.LittleEndian, &g.Data3); err != nil {
		return nil
	}
	if _, err := reader.Read(g.Data4[:]); err != nil {
		return nil
	}
	return g
}

// String returns the string representation of a SID
func (s *SID) String() string {
	if s == nil {
		return ""
	}

	// Calculate identifier authority value
	var idAuth uint64
	for i := 0; i < 6; i++ {
		idAuth = (idAuth << 8) | uint64(s.IdentifierAuthority[i])
	}

	result := fmt.Sprintf("S-%d-%d", s.Revision, idAuth)
	for _, sa := range s.SubAuthorities {
		result += fmt.Sprintf("-%d", sa)
	}
	return result
}

// GetRID returns the relative identifier (last sub-authority)
func (s *SID) GetRID() uint32 {
	if s == nil || len(s.SubAuthorities) == 0 {
		return 0
	}
	return s.SubAuthorities[len(s.SubAuthorities)-1]
}

// IsWellKnown returns the well-known name for a SID if known
func (s *SID) IsWellKnown() (string, bool) {
	sidStr := s.String()
	if name, ok := wellKnownSIDs[sidStr]; ok {
		return name, true
	}
	return "", false
}

// GetRIDName returns the well-known name for the RID if known
func (s *SID) GetRIDName() (string, bool) {
	if name, ok := wellKnownRIDs[s.GetRID()]; ok {
		return name, true
	}
	return "", false
}

// String returns the GUID as a string
func (g *GUID) String() string {
	if g == nil {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		g.Data1, g.Data2, g.Data3,
		g.Data4[0], g.Data4[1],
		g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7])
}

// Equals checks if two GUIDs are equal
func (g *GUID) Equals(other *GUID) bool {
	if g == nil || other == nil {
		return false
	}
	return g.Data1 == other.Data1 &&
		g.Data2 == other.Data2 &&
		g.Data3 == other.Data3 &&
		g.Data4 == other.Data4
}

// TemplatePermissions holds parsed permissions for a certificate template
type TemplatePermissions struct {
	Owner                   string
	EnrollmentRights        []string
	AutoEnrollmentRights    []string
	FullControlPrincipals   []string
	WriteOwnerPrincipals    []string
	WriteDACLPrincipals     []string
	WritePropertyPrincipals []string
	AllExtendedRights       []string
}

// ParseTemplatePermissions extracts human-readable permissions from security descriptor
func ParseTemplatePermissions(data []byte, sidResolver func(string) string) (*TemplatePermissions, error) {
	sd, err := ParseSecurityDescriptor(data)
	if err != nil {
		return nil, err
	}

	perms := &TemplatePermissions{}

	// Get owner
	if sd.OwnerSID != nil {
		sidStr := sd.OwnerSID.String()
		if sidResolver != nil {
			perms.Owner = sidResolver(sidStr)
		} else {
			perms.Owner = sidStr
		}
	}

	// Process DACL
	if sd.DACL == nil {
		return perms, nil
	}

	for _, ace := range sd.DACL.Entries {
		if ace.Type != ACCESS_ALLOWED_ACE_TYPE && ace.Type != ACCESS_ALLOWED_OBJECT_ACE_TYPE {
			continue
		}

		if ace.SID == nil {
			continue
		}

		sidStr := ace.SID.String()
		principal := sidStr
		if sidResolver != nil {
			principal = sidResolver(sidStr)
		}

		// Check for various permission types
		mask := ace.AccessMask

		// Full Control / GenericAll
		if mask&ADS_RIGHT_GENERIC_ALL != 0 {
			perms.FullControlPrincipals = appendUnique(perms.FullControlPrincipals, principal)
		}

		// Write Owner
		if mask&ADS_RIGHT_WRITE_OWNER != 0 {
			perms.WriteOwnerPrincipals = appendUnique(perms.WriteOwnerPrincipals, principal)
		}

		// Write DACL
		if mask&ADS_RIGHT_WRITE_DAC != 0 {
			perms.WriteDACLPrincipals = appendUnique(perms.WriteDACLPrincipals, principal)
		}

		// Write Property
		if mask&ADS_RIGHT_DS_WRITE_PROP != 0 {
			perms.WritePropertyPrincipals = appendUnique(perms.WritePropertyPrincipals, principal)
		}

		// Extended rights (Enroll / AutoEnroll)
		if mask&ADS_RIGHT_DS_CONTROL_ACCESS != 0 {
			if ace.ObjectType == nil {
				// All extended rights
				perms.AllExtendedRights = appendUnique(perms.AllExtendedRights, principal)
				perms.EnrollmentRights = appendUnique(perms.EnrollmentRights, principal)
				perms.AutoEnrollmentRights = appendUnique(perms.AutoEnrollmentRights, principal)
			} else if ace.ObjectType.Equals(&GUID_ENROLL) {
				perms.EnrollmentRights = appendUnique(perms.EnrollmentRights, principal)
			} else if ace.ObjectType.Equals(&GUID_AUTOENROLL) {
				perms.AutoEnrollmentRights = appendUnique(perms.AutoEnrollmentRights, principal)
			}
		}

		// GenericAll also implies enrollment
		if mask&ADS_RIGHT_GENERIC_ALL != 0 {
			perms.EnrollmentRights = appendUnique(perms.EnrollmentRights, principal)
		}
	}

	return perms, nil
}

func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}

// HasDangerousPermissions checks if any non-admin has dangerous permissions (ESC4)
func (p *TemplatePermissions) HasDangerousPermissions() bool {
	dangerous := append(p.FullControlPrincipals, p.WriteOwnerPrincipals...)
	dangerous = append(dangerous, p.WriteDACLPrincipals...)
	dangerous = append(dangerous, p.WritePropertyPrincipals...)

	for _, principal := range dangerous {
		// Check if it's a low-privilege group
		if isLowPrivilegeGroup(principal) {
			return true
		}
	}
	return false
}

// isLowPrivilegeGroup checks if the principal is a low-privilege group.
// Handles both bare names ("Domain Users") and domain-prefixed ("CORP\Domain Users").
func isLowPrivilegeGroup(principal string) bool {
	lowPrivGroups := []string{
		"Domain Users",
		"Authenticated Users",
		"Everyone",
		"Domain Computers",
		"Users",
	}
	for _, group := range lowPrivGroups {
		if strings.EqualFold(principal, group) {
			return true
		}
		// Check for DOMAIN\Group format (case-insensitive)
		suffix := "\\" + group
		if len(principal) > len(suffix) && strings.EqualFold(principal[len(principal)-len(suffix):], suffix) {
			return true
		}
	}
	return false
}
