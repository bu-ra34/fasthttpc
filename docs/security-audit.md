# Security review (2026-11)

This is an **internal, tool-assisted source review** of fasthttpc 0.6.0, done on
branch `security/audit-2026-11`. It is not a replacement for an independent
third-party audit: no fuzzing campaign, formal verification or timing
measurements were done. Every finding below was checked against the code, and
every *Fixed* finding has a regression test (`tests/test_security_audit.py`)
that fails on the code before the fix.

Severity scale: **Critical** (remote compromise of the TLS guarantees with no
preconditions), **High** (practical MITM / credential theft with modest
preconditions), **Medium** (exploitable under realistic but specific
conditions), **Low** (defence in depth, needs a malicious peer or an unusual
setup), **Info** (spec deviation or hardening suggestion with no known exploit).

No Critical or High findings were identified.

## Summary

| ID | Severity | Title | Status |
|---|---|---|---|
| FHC-01 | Medium | IP-literal hosts were verified against dNSName SANs | Fixed |
| FHC-02 | Medium | CR/LF/NUL accepted in outgoing headers, method and target (request injection) | Fixed |
| FHC-03 | Medium | Cookie `Domain=` accepted top-level domains and IP suffixes | Fixed |
| FHC-04 | Low | Lenient chunk-size parsing; chunk terminator not checked | Fixed |
| FHC-05 | Low | Unbounded HTTP/1.1 response header accumulation | Fixed |
| FHC-06 | Low | Loose parsing of the TLS 1.3 `Certificate` message | Fixed |
| FHC-07 | Low | No limit on decompressed response size | Open |
| FHC-08 | Low | No Public Suffix List for multi-label suffixes | Open |
| FHC-09 | Low | Conflicting `Transfer-Encoding` / `Content-Length` responses are not treated as errors | Open |
| FHC-10 | Info | TLS 1.3 cipher suite and ALPN not checked against what was offered | Open |
| FHC-11 | Info | Sync TLS 1.3 record layer accepts compatibility CCS after the handshake | Open |
| FHC-12 | Info | Unbounded count of TLS 1.2 warning alerts / TLS 1.3 handshake CCS records | Open |
| FHC-13 | Info | `rsa_pss_pss_*` CertificateVerify schemes accepted with rsaEncryption keys | Open |
| FHC-14 | Info | Low-level `TLSClientConnection(cert_validator=...)` hook can replace validation | Open |
| FHC-15 | Info | Legacy CBC (MAC-then-encrypt) Lucky13 mitigation is best effort | Open (by design) |
| FHC-16 | Info | DoH query string is built without URL-encoding the host name | Open |
| FHC-17 | Info | PSK resumption reuses the ticket's peer certificate without re-checking validity | Open |
| — | — | Async TLS handshake failure sends no alert to the server | Tracked separately |

## Findings

### FHC-01 — IP-literal hosts verified as DNS names (Medium, Fixed)

**Location:** `fasthttpc/security/cert_validator.py:241` (`_subject_for`), used at
line 294. Before the fix the verifier was always built with
`x509.DNSName(hostname)`.

**Description.** When the URL host is an IP address (`https://10.0.0.5/`,
`https://[::1]/`), the server identity must be matched against the
certificate's **iPAddress** SAN (RFC 9525 section 6.2, RFC 5280 section
4.2.1.6). fasthttpc passed the IP to `cryptography` as a DNS name, so:

* a certificate whose SAN is `dNSName: "10.0.0.5"` was **accepted** for
  `https://10.0.0.5/` (verified with `cryptography` 50.0.1);
* a correct certificate with `iPAddress: 10.0.0.5` was **rejected**.

**Exploit scenario.** Public CAs may not issue dNSName entries containing IP
addresses, so the realistic case is a private PKI (`verify="corp-ca.pem"`) or a
misissued certificate. An attacker who can obtain a certificate from a trusted
CA with a dNSName that spells the victim's IP can intercept connections that use
the IP literal. The rejection of correct IP-SAN certificates was a functional
bug that pushes users toward unsafe workarounds.

**Fix.** IP literals (with or without brackets) are verified as
`x509.IPAddress`; everything else stays `x509.DNSName`. This covers TLS 1.3,
TLS 1.2 and HTTP/3, which all go through `validate_server_certificate`.

### FHC-02 — Header / request-line injection (Medium, Fixed)

**Location:** HTTP/1.1 serialisation in `fasthttpc/session.py` (request line and
`f"{k}: {v}"` join) and `fasthttpc/async_session.py` (`_h1_exchange`); the same
values flow into HPACK/QPACK for HTTP/2 and HTTP/3. Validation added in
`fasthttpc/models/headers.py:21` (`check_header_field`) and
`fasthttpc/models/headers.py:36` (`check_request_line`), called at
`fasthttpc/session.py:725` and `fasthttpc/async_session.py:797`.

**Description.** Header names and values, cookie values (`cookies=`), the
method and the request target were written to the wire without any check.
A value such as `"x\r\nX-Injected: 1"` produced an extra header, and
`"x\r\n\r\nGET /admin HTTP/1.1\r\n..."` a second, attacker-chosen request on a
keep-alive connection. requests and httpx both reject these values.

**Exploit scenario.** An application forwards user-controlled data into a
header (`X-Forwarded-For`, a tracing ID, a cookie value). The attacker injects
CRLF and smuggles a request to the upstream, or a header that changes how the
upstream treats the request. For HTTP/2 and HTTP/3 such fields are "malformed"
(RFC 9113 section 8.2.1) and become a smuggling vector at h2-to-h1 gateways.

**Fix.** Before any connection is opened, every outgoing header name must be an
RFC 9110 token (HTTP/2-3 pseudo-headers allowed), values must not contain CR, LF
or NUL, the method must be a token, and the request target must not contain
control characters. Violations raise `ValueError` and nothing is sent.

### FHC-03 — Cookie `Domain=` scoped to a TLD or IP suffix (Medium, Fixed)

**Location:** `fasthttpc/cookies.py:63` (`_domain_attr_allowed`), used by
`parse_set_cookie` at line 131.

**Description.** The `Domain` attribute was accepted whenever the request host
ended with it. A response from `attacker.com` with `Set-Cookie: sid=x; Domain=com`
created a cookie that was sent to **every** `.com` host, and a response from
`10.0.0.1` with `Domain=0.0.1` created a cookie that was sent to `9.0.0.1`.
RFC 6265 section 5.3 says the attribute must be ignored for public suffixes and
that IP hosts only get host-only cookies.

**Exploit scenario.** A long-lived `Session` visits an attacker-controlled site
and later a bank. The attacker's cookie is sent to the bank (session fixation /
cookie tossing). Cookies set the same way by a legitimate site leak to every
other site under the same TLD.

**Fix.** On an IP host the `Domain` attribute is ignored (host-only cookie).
Single-label values (`com`, `.com`, `local`) are not accepted as a cookie
domain; the cookie stays host-only. Normal registrable domains
(`Domain=example.com` from `a.example.com`) work as before. Multi-label public
suffixes are still open, see FHC-08.

### FHC-04 — Lenient chunked-encoding parsing (Low, Fixed)

**Location:** `fasthttpc/protocol/http1_parser.py:47` (`parse_chunk_size`), used
at `fasthttpc/session.py:626`, `fasthttpc/async_session.py:955` and in
`HTTP1Parser._decode_chunked`. The terminator check is next to each "chunk sonu
CRLF" loop in `session.py` and `async_session.py`.

**Description.** Chunk sizes were parsed with `int(x, 16)`, which also accepts
`0x10`, `+5`, `-1`, `1_0` and surrounding whitespace. The two bytes after the
chunk data were thrown away without checking that they were CRLF.

**Exploit scenario.** Through an intermediary that frames the response
differently (strict RFC 9112 parsing), a malicious or compromised origin can
make the proxy and fasthttpc disagree on where a response ends. This enables
response splitting / queue poisoning on a shared connection. The impact is
limited because a client only talks to servers it chose.

**Fix.** Only 1-16 hex digits (followed by optional whitespace and chunk
extensions) are accepted, and the chunk data must be followed by CRLF.
Otherwise the connection fails with `ConnectionError`.

### FHC-05 — Unbounded response header block (Low, Fixed)

**Location:** `fasthttpc/session.py:834`, `fasthttpc/async_session.py:1060`; the
limit is `MAX_RESPONSE_HEADER_BYTES` (256 KiB) in
`fasthttpc/protocol/http1_parser.py:44`.

**Description.** The HTTP/1.1 readers buffered data until they saw `CRLFCRLF`,
with no size limit.

**Exploit scenario.** A malicious server (or any server reached through a
redirect) streams headers without ever ending the block and exhausts the
client's memory.

**Fix.** The connection fails with `ConnectionError` once the header block
exceeds 256 KiB, the same order as the HTTP/2 HPACK header-list limit.

### FHC-06 — Loose TLS 1.3 `Certificate` message parsing (Low, Fixed)

**Location:** `fasthttpc/security/cert_validator.py:118` and `:128`.

**Description.** A non-empty `certificate_request_context` (RFC 8446 section
4.4.2 requires it to be empty for server authentication), bytes after the
certificate list, and per-entry extensions that ran past the list were all
accepted. Chain and signature checks were not affected, so this is a strictness
issue, not an authentication bypass.

**Fix.** These cases now raise `CertificateValidationError`.

### FHC-07 — No limit on decompressed body size (Low, Open)

**Location:** `fasthttpc/protocol/http1_parser.py:122` (`_decompress`),
`fasthttpc/streaming.py`.

A small gzip/brotli/zstd body can expand to gigabytes when the body is buffered
(the default when `stream=False`). requests and httpx behave the same way.
**Recommendation:** add a `max_decompressed_size` (or reuse a response-size limit)
and use incremental decompressors with `max_length` in the buffered path too.

### FHC-08 — No Public Suffix List (Low, Open)

**Location:** `fasthttpc/cookies.py:63`.

After FHC-03, `Domain=co.uk` or `Domain=github.io` is still accepted from
`a.co.uk` / `x.github.io`. **Recommendation:** check the attribute against the
Public Suffix List (an optional dependency, or a vendored snapshot), as
browsers do.

### FHC-09 — Conflicting message framing not treated as an error (Low, Open)

**Location:** `fasthttpc/session.py:529` (`_body_framing`),
`fasthttpc/async_session.py:901` (`_h1_framing`).

A response with both `Transfer-Encoding: chunked` and `Content-Length` is decoded
as chunked (correct) but the connection is kept for reuse. A `Transfer-Encoding`
in which `chunked` is not the final coding is still treated as chunked (substring
match). RFC 9112 section 6.1/6.3 says such messages should be treated as framing
errors and the connection closed. **Recommendation:** parse the coding list,
require `chunked` to be last, and close the connection when both headers are
present.

### FHC-10 — Negotiated suite / ALPN not checked against the offer (Info, Open)

**Location:** `fasthttpc/security/tls_adapter.py:897`,
`fasthttpc/tls13/connection.py:626` (`_set_suite`) and `:78` (`parse_alpn`).

The TLS 1.3 paths accept any of the three TLS 1.3 suites and any ALPN value,
without checking that the ClientHello offered them (RFC 8446 section 4.1.3,
RFC 7301 section 3.2). The transcript is authenticated, so an on-path attacker
cannot change these values. Only the authenticated server itself can pick
something unexpected. (The TLS 1.2 path already checks both.)
**Recommendation:** compare against the parsed ClientHello, as `tls12.py` does.

### FHC-11 — CCS tolerated after the TLS 1.3 handshake (Info, Open)

**Location:** `fasthttpc/security/tls_adapter.py:466` (`EncryptedSocket.recv_record`).

RFC 8446 section 5 requires an `unexpected_message` abort when a CCS arrives
after the peer's Finished. The sync path drops it silently (a code comment says
this is intentional for a performance test). The sans-IO path already rejects it.
There is no known impact because the record carries no data.

### FHC-12 — Unbounded warning alerts / compatibility CCS (Info, Open)

**Location:** `fasthttpc/security/tls12.py:1175`,
`fasthttpc/tls13/connection.py:388`.

Before the handshake is authenticated, an on-path attacker can inject any number
of TLS 1.2 warning alerts or TLS 1.3 compatibility CCS records, and each one is
silently dropped. The cost is bounded by bandwidth. **Recommendation:** cap the
count, as is already done for `HelloRequest`.

### FHC-13 — `rsa_pss_pss_*` accepted with rsaEncryption keys (Info, Open)

**Location:** `fasthttpc/security/cert_validator.py:333` and the following lines.

RFC 8446 section 4.2.3 binds `rsa_pss_pss_*` to certificates with an RSASSA-PSS
public key. fasthttpc verifies these schemes with any RSA key. The signature is
still verified, so this is not exploitable. **Recommendation:** require the PSS
key OID for 0x0809-0x080B.

### FHC-14 — Low-level validation hook (Info, Open)

**Location:** `fasthttpc/tls13/connection.py` (`cert_validator=` argument),
also reachable through `SyncTLSSocket.negotiate` / `AsyncTLSStream.negotiate`
`**conn_kwargs`.

A caller of the low-level sans-IO API can pass a validator that accepts anything.
`Session` and `AsyncSession` never pass it, and it is not documented, so the
"no way to disable verification" guarantee holds for the public client API.
**Recommendation:** rename it to a private/test-only parameter, or require it to
wrap (not replace) `validate_server_certificate`.

### FHC-15 — Lucky13 mitigation is best effort (Info, Open by design)

**Location:** `fasthttpc/security/tls12_legacy.py:205` (`_open_mte`).

Only with `legacy_tls=True` and a server that refuses Encrypt-then-MAC. Padding
and MAC errors share a single error path and the hashed length is padded out,
but pure Python cannot give constant-time guarantees. This is documented, and
the mode is off by default. **Recommendation:** keep it opt-in, and consider
refusing MtE CBC unless the user opts in a second time.

### FHC-16 — DoH query built without encoding (Info, Open)

**Location:** `fasthttpc/protocol/dns_over_https.py:97`.

The host name is put into `?name=...` without percent-encoding. A host name that
contains `&` or `#` can change the query. Certificate validation for the real
target still runs against the original host name, so a wrong answer cannot lead
to an unauthenticated connection. **Recommendation:** use `urllib.parse.quote`.

### FHC-17 — Resumed sessions reuse the stored peer certificate (Info, Open)

**Location:** `fasthttpc/tls13/connection.py:585` and the matching code in
`tls_adapter.py`.

PSK resumption is **off by default**. When it is on, a resumed connection reports
the certificate validated on the original handshake (tickets live at most 7
days), and the certificate's expiry is not checked again. **Recommendation:**
drop tickets whose `peer_certificate.not_valid_after_utc` has passed.

## Checked and found OK

**Certificate validation**

* Chain building, signatures, basicConstraints, keyUsage/EKU (serverAuth),
  name constraints, path length and validity of every chain element are
  delegated to `cryptography.x509.verification` (Rust, webpki-derived) with
  `max_chain_depth(32)`. No hand-written ASN.1 or signature code.
* Trust store: `certifi` plus the first system bundle, or **only** the PEM given
  with `verify=`. It is cached by (path, mtime, size), so a changed file is
  reloaded.
* Wildcard matching is handled by the same verifier (RFC 6125 style: a single
  wildcard, in the left-most label only).
* A failed validation is never retried and is never downgraded to a warning.
  HTTP/3 uses the same validator before any request is sent, and with
  `verify=` aioquic verifies as well.

**`verify=False`**

* `resolve_verify` raises `ValueError` for `False` and `TypeError` for anything
  that is neither `True` nor a path. An empty or missing path raises
  `FileNotFoundError`. No environment variable or hidden flag disables
  validation. The stdlib-ssl paths (`impersonate=None`, DoH) use
  `ssl.create_default_context()` with hostname checking. aioquic's
  `CERT_NONE` is compensated by fasthttpc's own validation, and aioquic always
  verifies the CertificateVerify signature. See FHC-14 for the low-level hook.

**TLS 1.3** (both the sync `TLSAdapter` and the sans-IO `TLSClientConnection`)

* Message order is enforced (RFC 8446 appendix A.1): a single optional
  CertificateRequest, and Finished is rejected unless Certificate and
  CertificateVerify were both processed (or a PSK was accepted). A PSK handshake
  that carries a Certificate is rejected.
* CertificateVerify is mandatory. It uses the correct context string and
  transcript hash, the scheme must be one we offered, `rsa_pkcs1_*` is
  forbidden, ECDSA schemes are bound to their curve, and the PSS salt equals
  the hash length.
* Server Finished is compared with `hmac.compare_digest`. The client Finished
  and the application secrets use the right transcript ranges, and the
  resumption secret covers the client Finished.
* HelloRetryRequest: only one is accepted. The group must be advertised, not
  already sent, and supported. Suite and group must stay the same in
  ServerHello2. The transcript uses `message_hash`. A TLS 1.2 ServerHello after
  an HRR is rejected, and so is a cookie-less, group-less HRR.
* ServerHello: duplicate extensions and session-id echo mismatches are rejected,
  and the version must be negotiated through `supported_versions`.
* Record layer: nonce = IV XOR the 64-bit sequence number. Sequence overflow is
  checked. Limits are 2^14+256 bytes of ciphertext and 2^14(+1) of plaintext.
  The AAD is the received header. Zero padding is stripped and all-padding
  records are rejected. Handshake messages may not cross a key change, and
  KeyUpdate must end at a record boundary. Plaintext alerts and handshake
  records are rejected once encryption is on. `record_size_limit` < 64 is
  rejected.
* Key exchange: the x25519 all-zero shared secret is rejected. P-256 and P-384
  points must be uncompressed and on the curve (`from_encoded_point`).
  ML-KEM hybrid sizes are checked.
* 0-RTT is not implemented. PSK resumption is off by default, uses
  `psk_dhe_ke` only, and tickets are single-use and keyed by
  host/port/ca_path/client certificate.

**TLS 1.2 subset**

* The RFC 8446 section 4.1.3 DOWNGRD sentinels are checked first, in default
  and legacy mode. TLS 1.1 and lower is always rejected.
* Extended Master Secret and RFC 5746 `renegotiation_info` are mandatory by
  default. Renegotiation is refused (`no_renegotiation`, at most 3 times, then
  the connection is closed).
* ServerHello: the extension whitelist is enforced, every extension must have
  been offered, the suite must have been offered, and ALPN must be one we
  offered.
* ServerKeyExchange: the signature covers both randoms and the parameters, the
  algorithm must have been offered, and the key type must match the suite.
  MD5, SHA-1 and SHA-224 are rejected (legacy mode allows SHA-1 only). The curve
  must have been offered, and the points are validated.
* Finished verify_data is checked in constant time and must be exactly 12
  bytes. CCS ordering is enforced and the sequence-number limit is respected.

**Legacy mode**

* The default is `False` in `Session`, `AsyncSession`, `TLSImpersonator`,
  `TLSAdapter.negotiate` and `TLS12ClientConnection`. `normalize_legacy` only
  accepts booleans and explicitly refuses `"tls1.0"`-style strings.
* Encrypt-then-MAC is preferred. Padding and MAC errors raise one
  indistinguishable `bad_record_mac`. CBC IVs come from `os.urandom`.

**Randomness and keys**

* `os.urandom` and `cryptography` key generation are used for client randoms,
  session IDs, key shares, CBC IVs, the static-RSA premaster, Digest cnonces
  and WebSocket keys. `random.SystemRandom` is used for GREASE. The only
  `random.Random` use is the GREASE *setting identifier* in HTTP/3 SETTINGS,
  which is not secret.

**HTTP layer**

* HPACK: integers capped at 2^32, a 256 KiB header-list limit, table-size
  updates checked against the advertised value and allowed only at the start
  of a block, a CONTINUATION flood limit, and interleaved frames rejected while
  a header block is open.
* Redirects: `Authorization`, `Cookie` and `Proxy-Authorization` are stripped
  when the origin (scheme, host, port) changes. Explicit and session `auth=` and
  per-request `cookies=` are only applied to the original origin. `.netrc` is
  looked up per host. 301/302/303 drop the body, and `max_redirects` defaults
  to 10. `http://` URLs are still fetched over TLS in the HTTP paths, so a
  redirect cannot downgrade to cleartext.
* Cookies: `Secure` cookies are only sent over https, host-only matching works,
  and path matching follows RFC 6265 section 5.1.4.
* Proxies: the CONNECT response size is capped (64 KiB), only a 2xx answer
  opens the tunnel, 407 is reported, and TLS to the target runs inside the
  tunnel (the proxy never sees plaintext). SOCKS5 field lengths are checked.
  The proxy password is masked in `repr`.
* Digest auth: the strongest offered algorithm is chosen (SHA-256 over MD5). A
  rejected preemptive credential is not retried. The state is per origin, and
  the cnonce comes from `os.urandom`.
* mTLS: the client key never leaves the process. If no suitable
  certificate/scheme is available, an empty Certificate is sent. A warning is
  issued when the key file is readable by group or others (POSIX).
