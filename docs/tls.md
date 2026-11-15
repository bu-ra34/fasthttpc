# TLS

## Versions

fasthttpc prefers **TLS 1.3** (including HelloRetryRequest with cookie). If the
server selects TLS 1.2, a **safe subset** is supported:

- ECDHE (x25519, secp256r1, secp384r1) with ECDSA/RSA certificates.
- AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305.
- Extended Master Secret and `renegotiation_info` are **mandatory**; the
  `DOWNGRD` sentinel in ServerHello.random is checked.
- Rejected with an explicit error: CBC, static RSA, DHE, PSK, export/anonymous,
  SHA-1/MD5/SHA-224 signatures, TLS 1.1 and below, renegotiation.

CBC, static RSA, SHA-1 signatures and servers without EMS can be allowed with
the opt-in [legacy TLS](features/legacy-tls.md) mode. TLS 1.0/1.1 are never
supported.

This applies to fasthttpc's own TLS stack, which `Session` always uses and
`AsyncSession` uses whenever `impersonate` is set (the default).
`AsyncSession(impersonate=None)` uses Python's `ssl` module instead.

## Verification and `verify=`

Server authentication checks the certificate chain and hostname, the
**CertificateVerify** signature and the server **Finished** MAC. All are
mandatory. IP-address hosts are matched against iPAddress SANs.

```python
Session(verify=True)                 # default: certifi + system store
Session(verify="/etc/corp/ca.pem")   # trust exactly this PEM file
Session(verify=False)                # ValueError, by design
```

For a self-signed test server pass that certificate (or its CA) as `verify=`.
`FileNotFoundError` is raised if the path does not exist.

## Client certificates

Both TLS 1.3 and TLS 1.2 answer a server's CertificateRequest. With `cert=` the
client certificate is sent; without it an empty Certificate is sent and the
server decides. See [client certificates](features/client-certs.md).

## Session resumption

TLS 1.3 PSK resumption (RFC 8446 section 4.6.1) is implemented for the sync and
async clients but is **off by default**. Turn it on for the whole process:

```python
from fasthttpc.security import session_tickets
session_tickets.enable_resumption(True)     # or FASTHTTPC_TLS_RESUMPTION=1
```

When enabled, only `psk_dhe_ke` is used (a fresh ECDHE exchange on every
connection, so forward secrecy is kept). Tickets are single-use, live at most
7 days, and are keyed by host, port, trust store and client certificate. A
resumed connection does not re-validate the server certificate; see FHC-17 in
the [security review](security-audit.md).

Not supported: 0-RTT (early data), TLS 1.2 session resumption, and resumption
over HTTP/3. With resumption off, every connection does a full handshake and
`NewSessionTicket` messages are parsed and discarded.

## Key exchange groups

x25519, secp256r1, secp384r1, and the hybrid post-quantum group
**X25519MLKEM768** when the installed `cryptography` provides ML-KEM (version
47 or newer). X25519MLKEM768 is offered by the `chrome_131` and `firefox_133`
profiles, not by `safari_18` or `default`; see [profiles](profiles.md).
secp521r1, x448 and ffdhe are not implemented; no key_share is sent for them.

See also: [client certificates](features/client-certs.md),
[legacy TLS](features/legacy-tls.md), [security model](security.md).
