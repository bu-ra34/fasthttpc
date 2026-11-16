# Client certificates (mTLS)

`cert=` is a session-level, keyword-only option of `Session` and
`AsyncSession` (there is no per-request `cert=`):

```python
from fasthttpc import Session
from fasthttpc.security.client_cert import ClientCert

Session(cert="client.pem")                           # certificate + key in one PEM
Session(cert=("client.crt", "client.key"))           # separate files
Session(cert=("client.crt", "client.key", "secret")) # encrypted PEM / PKCS#8 key
Session(cert=ClientCert.from_pkcs12("id.p12", "secret"))
```

- Key types: RSA (at least 2048 bits), ECDSA P-256 and P-384, Ed25519. Other
  types (DSA, Ed448, P-521, smaller RSA keys) are rejected with
  `ClientCertError` (a `ValueError`).
- The leaf is the certificate that matches the key; the other certificates in
  the file are sent as the chain.
- Works with TLS 1.3 and TLS 1.2 (including `legacy_tls` static RSA), directly
  or through a proxy, and for `wss://` WebSockets.
- If the server's CertificateRequest does not accept the certificate (CA list
  or signature schemes), an empty Certificate is sent and the server decides.
  Without `cert=`, a CertificateRequest is also answered with an empty
  Certificate.
- The certificate identity is part of the connection-pool and session-ticket
  keys, so connections made with different certificates are never mixed.
- A warning is logged if the key file is readable by group or others (POSIX).
  The PEM text and password are not kept after loading; the object cannot be
  pickled or copied.

## Not supported

- Post-handshake client authentication (TLS 1.3 `post_handshake_auth`).
- `AsyncSession(impersonate=None, cert=...)` raises `ValueError` (that path uses
  stdlib `ssl`).
- HTTP/3: when `cert=` is set, HTTP/3 is not used; `http3="force"` with
  `cert=` raises `ValueError`.
