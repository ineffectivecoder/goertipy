package ldap

import (
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// Client wraps an LDAP connection with helper methods
type Client struct {
	conn                       *ldap.Conn
	baseDN                     string
	configurationNamingContext string
	domain                     string
}

// Options for LDAP connection
type Options struct {
	Server   string
	Port     int
	UseTLS   bool
	Username string
	Password string
	Domain   string

	// NTLM hash authentication (LM:NT or :NT format)
	NTHash string
	LMHash string

	// InsecureSkipVerify skips TLS certificate verification
	InsecureSkipVerify bool
}

// ParseHashes parses a hash string in LM:NT or :NT format into LM and NT components
func ParseHashes(hashes string) (lmHash, ntHash string, err error) {
	if hashes == "" {
		return "", "", nil
	}

	parts := strings.SplitN(hashes, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid hash format, expected LM:NT or :NT")
	}

	lmHash = parts[0]
	ntHash = parts[1]

	// Validate hex encoding
	if ntHash == "" {
		return "", "", fmt.Errorf("NT hash is required")
	}
	if _, err := hex.DecodeString(ntHash); err != nil {
		return "", "", fmt.Errorf("invalid NT hash hex: %w", err)
	}
	if lmHash != "" {
		if _, err := hex.DecodeString(lmHash); err != nil {
			return "", "", fmt.Errorf("invalid LM hash hex: %w", err)
		}
	}

	return lmHash, ntHash, nil
}

// Connect establishes an LDAP connection
func Connect(opts Options) (*Client, error) {
	var conn *ldap.Conn
	var err error

	address := fmt.Sprintf("%s:%d", opts.Server, opts.Port)

	if opts.UseTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: opts.InsecureSkipVerify,
			ServerName:         opts.Server,
		}
		conn, err = ldap.DialTLS("tcp", address, tlsConfig)
	} else {
		conn, err = ldap.Dial("tcp", address)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	client := &Client{
		conn:   conn,
		domain: opts.Domain,
	}

	// Bind with credentials
	if opts.Username != "" {
		bindUser := opts.Username
		// If username doesn't contain @ or \, prepend domain
		if !strings.Contains(bindUser, "@") && !strings.Contains(bindUser, "\\") {
			if opts.Domain != "" {
				bindUser = fmt.Sprintf("%s@%s", opts.Username, opts.Domain)
			}
		}

		if opts.NTHash != "" {
			// NTLM hash authentication using pass-the-hash
			ntBytes, err := hex.DecodeString(opts.NTHash)
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("failed to decode NT hash: %w", err)
			}

			// Use NTLMv2 bind with the hash as the password equivalent
			// The go-ldap library supports NTLM via NTLMBind
			err = conn.NTLMBind(opts.Domain, opts.Username, string(ntBytes))
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("NTLM bind failed: %w", err)
			}
		} else {
			// Standard simple bind
			if err := conn.Bind(bindUser, opts.Password); err != nil {
				conn.Close()
				return nil, fmt.Errorf("failed to bind: %w", err)
			}
		}
	}

	// Get root DSE to discover naming contexts
	if err := client.discoverNamingContexts(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to discover naming contexts: %w", err)
	}

	return client, nil
}

// discoverNamingContexts queries the RootDSE for naming contexts
func (c *Client) discoverNamingContexts() error {
	searchRequest := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext", "configurationNamingContext"},
		nil,
	)

	result, err := c.conn.Search(searchRequest)
	if err != nil {
		return err
	}

	if len(result.Entries) == 0 {
		return fmt.Errorf("no RootDSE entry found")
	}

	entry := result.Entries[0]
	c.baseDN = entry.GetAttributeValue("defaultNamingContext")
	c.configurationNamingContext = entry.GetAttributeValue("configurationNamingContext")

	return nil
}

// Close closes the LDAP connection
func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// BaseDN returns the default naming context
func (c *Client) BaseDN() string {
	return c.baseDN
}

// ConfigurationNC returns the configuration naming context
func (c *Client) ConfigurationNC() string {
	return c.configurationNamingContext
}

// Domain returns the domain name
func (c *Client) Domain() string {
	return c.domain
}

// Search performs an LDAP search
func (c *Client) Search(baseDN string, scope int, filter string, attributes []string) ([]*ldap.Entry, error) {
	searchRequest := ldap.NewSearchRequest(
		baseDN,
		scope,
		ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		attributes,
		nil,
	)

	result, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	return result.Entries, nil
}

// SearchOne performs a search and returns a single entry
func (c *Client) SearchOne(baseDN string, scope int, filter string, attributes []string) (*ldap.Entry, error) {
	entries, err := c.Search(baseDN, scope, filter, attributes)
	if err != nil {
		return nil, err
	}

	if len(entries) == 0 {
		return nil, nil
	}

	return entries[0], nil
}

// Conn returns the underlying LDAP connection for advanced operations
func (c *Client) Conn() *ldap.Conn {
	return c.conn
}
