# Known limits

## TLS

- TLS 1.3 PSK session resumption is implemented but **off by default**. Turn it
  on process-wide with `fasthttpc.security.session_tickets.enable_resumption(True)`
  or the environment variable `FASTHTTPC_TLS_RESUMPTION=1`. TLS 1.2 has no
  resumption, and there is no 0-RTT (early data) at all.
- Hybrid post-quantum X25519MLKEM768 is offered by the Chrome and Firefox
  profiles and `safari_27`, but only when the installed `cryptography` provides
  ML-KEM (version 47 or newer). Without it, the group is dropped from the
  ClientHello, which then no longer matches the browser. `chrome_158`'s ML-DSA
  signature schemes likewise need `cryptography` 48 or newer, which provides
  ML-DSA. On older versions they are dropped.
- secp521r1, x448, ffdhe2048 and ffdhe3072 never get a key_share in the first
  ClientHello (the browsers don't send one either). A server that accepts only
  one of them costs a HelloRetryRequest round trip. The group must be one the
  profile advertises: Firefox and Safari advertise secp521r1, only `firefox_133`
  advertises ffdhe2048/3072, Chrome and `default` advertise none of them, and no
  profile advertises x448. A HelloRetryRequest or TLS 1.2 ServerKeyExchange for
  a group the profile did not advertise is rejected.
- ffdhe is TLS 1.3 only (TLS 1.2 DHE stays rejected), and ffdhe4096/6144/8192
  are not implemented. ffdhe uses `cryptography`'s finite-field Diffie-Hellman,
  which `cryptography` has deprecated. If a future version removes it, the ffdhe
  groups are still advertised (the ClientHello does not change), but a
  HelloRetryRequest asking for one gets an explicit error.
- TLS 1.2: ECDHE + AEAD only by default. CBC and static RSA need
  `legacy_tls=True` ([legacy TLS](features/legacy-tls.md)); DHE, PSK and
  TLS 1.1 or lower are always rejected.
- TLS 1.2 servers without Extended Master Secret (RFC 7627) or
  `renegotiation_info` are refused at ServerHello unless `legacy_tls=True`
  (example: `badssl.com`). The error is
  `handshake_failure: Sunucu Extended Master Secret (RFC 7627) kabul etmedi`;
  it comes before the certificate check, so such a server never reports a
  certificate error.
- No post-handshake client authentication (TLS 1.3 `post_handshake_auth`).

## HTTP

- `http://` is plain HTTP/1.1 only: no h2c (cleartext HTTP/2) and no HTTP/3.
  There is no HSTS, so an `http://` URL is never upgraded to `https://`. (Up to
  0.6.2, `http://` URLs were fetched over TLS.)
- HPACK Huffman encoding missing (small HTTP/2 fingerprint deviation).
- HTTP/2 server push is disabled (`ENABLE_PUSH=0`). PRIORITY frames are not
  sent; the HEADERS priority field follows the profile.
- Concurrent HTTP/2 streams on one connection are an `AsyncSession` feature;
  `Session` runs one request at a time on an HTTP/2 connection.
- HTTP/3 is experimental: it is not used through proxies or with `cert=`, is
  not used under trio (`http3=True` falls back, `"force"` raises
  `Http3ConnectError`), buffers whole response bodies, never uses resumption or
  0-RTT, and its QUIC TLS handshake is aioquic's (no browser ClientHello). It has
  only been tested against a local aioquic server. See [HTTP/3](features/http3.md).

## Client

- `Session` is not thread-safe.
- `Timeout.write` is not enforced separately on the sync side (sends use the
  request's `read` socket timeout, capped by the remaining `total`).
- `Timeout.total` does not bound reading a streamed (`stream=True`) body after
  the headers have arrived; each read there is bounded by `read`.
- On PyPy, zstd decoding needs `pip install "fasthttpc[zstd]"` (zstandard has no
  PyPy wheels); without it a zstd-encoded response raises `MissingDecoderError`.
- `https://` proxies are not supported (an explicit or environment proxy with
  that scheme raises `ValueError`). Proxy and CA bundle environment variables
  are read once, when the session is created; `SSL_CERT_DIR` is not supported.
  `NO_PROXY` CIDR entries only match IP-literal targets (names are not resolved).
- `AsyncSession(impersonate=None)` uses Python's `ssl` module: HTTP/1.1 only, no
  `cert=`, and `legacy_tls` has no effect there.
- Three browser families are modelled; profiles age. There is no Edge profile
  (see [Profiles](profiles.md)).
- Pure-Python framing is slower than OpenSSL for bulk transfers.

## Browser fingerprint deviations

The current profiles (`chrome_158`, `firefox_160`, `safari_27`) are built from
browser source code and published captures. The [Profiles](profiles.md) page lists
the sources. The table below lists everything known not to match the real browser:

| Profile | Deviation |
|---|---|
| `chrome_158` | Real Chrome retries with the server's trust anchors if the first chain is not trusted (`trust_anchors` in EncryptedExtensions). fasthttpc sends the extension, ignores the server's answer and does not retry. Certificate verification is unchanged. |
| `chrome_158` | The trust anchor list is the Chrome Root Store's at Chromium 158. Real Chrome updates it through the component updater, so the 186-byte extension can drift between Chrome releases. |
| `chrome_158` | The ECH GREASE AEAD is chosen at random between AES-128-GCM and ChaCha20. Chrome picks AES when the CPU has AES hardware. |
| `chrome_158` | Validated against a real capture from Chrome **153**, plus the Chromium 158 source. No Chrome 158 binary capture was available. |
| `firefox_160` | The ECH GREASE payload length (240) is estimated from NSS's padding formula, not measured. Real Firefox derives it from its inner ClientHello. |
| `firefox_160` | The `zstd` certificate-compression entry is only advertised when `zstandard` is installed, and `brotli` only when `brotli` is installed. |
| `firefox_160` | The TLS values come from the Firefox 160 source. The newest real capture available was Firefox 155. |
| `safari_27` | Built from the Safari 27.0 capture data; 27.1/27.2 are assumed to have the same network stack (only the User-Agent says 27.2). |
| all | HTTP/3 uses aioquic's ClientHello (no browser TLS fingerprint over QUIC); the Chrome QUIC profile does not send the `H3_DATAGRAM` (0x33) setting current Chrome sends. |

## Project

- Young project with a small user base. There has been an internal security
  review ([Security review (2026-11)](security-audit.md), with open findings
  such as no limit on decompressed body size), but no external audit.
