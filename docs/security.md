# Security model

Every TLS connection authenticates the server with three mandatory checks:

| Check | What it proves |
|---|---|
| Certificate chain | A trusted CA signed it, hostname matches, validity period |
| **CertificateVerify** | The peer holds the certificate's private key (RFC 8446 section 4.4.3) |
| **Server Finished** | The handshake transcript was not altered (section 4.4.4) |

Trust anchors: `certifi` plus the system store, or exactly the PEM given as
`verify=`. `verify=False` raises `ValueError`. Certificate errors are never
retried. TLS 1.2 additionally requires EMS and `renegotiation_info`, detects
downgrade sentinels and rejects weak suites (unless `legacy_tls=True`, see
[legacy TLS](features/legacy-tls.md)).

The table describes fasthttpc's own TLS stack. Two paths use Python's `ssl`
module with `ssl.create_default_context()` instead, which also always verifies
the chain and hostname: `AsyncSession(impersonate=None)` and the DNS-over-HTTPS
resolver. For HTTP/3, fasthttpc runs the same certificate validator on the
QUIC handshake before any request is sent.

## Not covered

- No independent third-party audit; the stack is young. An internal review and
  its open items are in [Security review (2026-11)](security-audit.md).
- Constant-time behaviour is only as good as `cryptography`/OpenSSL primitives;
  protocol logic is pure Python.
- Fingerprint impersonation is not an anti-detection guarantee.

Report vulnerabilities privately through GitHub security advisories.
