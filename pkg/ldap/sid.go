package ldap

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// SIDResolver resolves SIDs to human-readable names via LDAP
type SIDResolver struct {
	client *Client
	cache  map[string]string
}

// NewSIDResolver creates a new SID resolver
func NewSIDResolver(client *Client) *SIDResolver {
	return &SIDResolver{
		client: client,
		cache:  make(map[string]string),
	}
}

// Resolve converts a SID string to a human-readable name
func (r *SIDResolver) Resolve(sid string) string {
	// Check cache first
	if name, ok := r.cache[sid]; ok {
		return name
	}

	// Check well-known SIDs
	if name := r.resolveWellKnown(sid); name != "" {
		r.cache[sid] = name
		return name
	}

	// Try to resolve via LDAP
	name := r.resolveLDAP(sid)
	if name != "" {
		r.cache[sid] = name
		return name
	}

	// Return SID as-is if resolution fails
	return sid
}

// resolveWellKnown handles well-known SIDs
func (r *SIDResolver) resolveWellKnown(sid string) string {
	wellKnown := map[string]string{
		"S-1-0-0":  "Null SID",
		"S-1-1-0":  "Everyone",
		"S-1-2-0":  "Local",
		"S-1-3-0":  "Creator Owner",
		"S-1-3-1":  "Creator Group",
		"S-1-5-7":  "Anonymous",
		"S-1-5-9":  "Enterprise Domain Controllers",
		"S-1-5-10": "Self",
		"S-1-5-11": "Authenticated Users",
		"S-1-5-18": "Local System",
		"S-1-5-19": "Local Service",
		"S-1-5-20": "Network Service",
	}

	if name, ok := wellKnown[sid]; ok {
		return name
	}

	return ""
}

// resolveLDAP resolves a SID via LDAP query
func (r *SIDResolver) resolveLDAP(sid string) string {
	// Convert SID string to binary format for LDAP search
	binarySID := sidStringToBinary(sid)
	if binarySID == "" {
		return ""
	}

	// Search for the object with this SID
	filter := fmt.Sprintf("(objectSid=%s)", binarySID)
	entries, err := r.client.Search(
		r.client.BaseDN(),
		ldap.ScopeWholeSubtree,
		filter,
		[]string{"sAMAccountName", "name", "distinguishedName"},
	)
	if err != nil || len(entries) == 0 {
		return ""
	}

	entry := entries[0]

	// Get sAMAccountName or name
	name := entry.GetAttributeValue("sAMAccountName")
	if name == "" {
		name = entry.GetAttributeValue("name")
	}

	// Extract domain from DN and prepend
	if name != "" {
		domain := extractDomainFromDN(entry.GetAttributeValue("distinguishedName"))
		if domain != "" {
			return fmt.Sprintf("%s\\%s", strings.ToUpper(domain), name)
		}
		return name
	}

	return ""
}

// sidStringToBinary converts a SID string (S-1-5-...) to LDAP binary format
func sidStringToBinary(sid string) string {
	if !strings.HasPrefix(sid, "S-") {
		return ""
	}

	parts := strings.Split(sid, "-")
	if len(parts) < 3 {
		return ""
	}

	var result strings.Builder

	// Revision (always 1)
	result.WriteString(fmt.Sprintf("\\%02x", 1))

	// Number of sub-authorities
	numSubAuth := len(parts) - 3
	result.WriteString(fmt.Sprintf("\\%02x", numSubAuth))

	// Identifier authority (48 bits, big-endian)
	var idAuth uint64
	fmt.Sscanf(parts[2], "%d", &idAuth)
	for i := 5; i >= 0; i-- {
		result.WriteString(fmt.Sprintf("\\%02x", (idAuth>>(i*8))&0xFF))
	}

	// Sub-authorities (32 bits each, little-endian)
	for i := 3; i < len(parts); i++ {
		var subAuth uint32
		fmt.Sscanf(parts[i], "%d", &subAuth)
		result.WriteString(fmt.Sprintf("\\%02x\\%02x\\%02x\\%02x",
			subAuth&0xFF,
			(subAuth>>8)&0xFF,
			(subAuth>>16)&0xFF,
			(subAuth>>24)&0xFF))
	}

	return result.String()
}

// extractDomainFromDN extracts the domain name from a distinguished name
func extractDomainFromDN(dn string) string {
	parts := strings.Split(dn, ",")
	var domainParts []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "DC=") {
			domainParts = append(domainParts, strings.TrimPrefix(strings.TrimPrefix(part, "DC="), "dc="))
		}
	}
	if len(domainParts) > 0 {
		return domainParts[0] // Return first DC component as NetBIOS name
	}
	return ""
}
