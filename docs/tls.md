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

## Verification and `verify=`

Server authentication checks the certificate chain and hostname, the
**CertificateVerify** signature and the server **Finished** MAC. All are
mandatory.

```python
Session(verify=True)                 # default: certifi + system store
Session(verify="/etc/corp/ca.pem")   # trust exactly this PEM file
Session(verify=False)                # ValueError, by design
```

For a self-signed test server pass that certificate (or its CA) as `verify=`.
`FileNotFoundError` is raised if the path does not exist.

## Session resumption

Not supported: there is no PSK resumption and no 0-RTT. Every connection does a
full handshake (`NewSessionTicket` is parsed and discarded).

## Key exchange groups

x25519, secp256r1, secp384r1. Hybrid post-quantum groups, secp521r1 and ffdhe
are not implemented; no key_share is sent for them.

See also: [client certificates](features/client-certs.md),
[legacy TLS](features/legacy-tls.md), [security model](security.md).
