# Known limits

## TLS

- TLS 1.3 PSK session resumption is implemented but **off by default**. Turn it
  on process-wide with `fasthttpc.security.session_tickets.enable_resumption(True)`
  or the environment variable `FASTHTTPC_TLS_RESUMPTION=1`. TLS 1.2 has no
  resumption, and there is no 0-RTT (early data) at all.
- Hybrid post-quantum X25519MLKEM768 is offered only by the `chrome_131` and
  `firefox_133` profiles, and only when the installed `cryptography` provides
  ML-KEM (version 47 or newer). Without it the group is dropped from the
  ClientHello, which then no longer matches the browser.
- secp521r1, x448 and ffdhe key exchange are not implemented. Profiles that
  advertise them in `supported_groups` (Firefox, Safari) send no key_share for
  them; a server that asks for one through HelloRetryRequest gets an explicit
  error.
- TLS 1.2: ECDHE + AEAD only by default. CBC and static RSA need
  `legacy_tls=True` ([legacy TLS](features/legacy-tls.md)); DHE, PSK and
  TLS 1.1 or lower are always rejected.
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
- Three browser families are modelled; profiles age.
- Pure-Python framing is slower than OpenSSL for bulk transfers.

## Project

- Young project with a small user base. There has been an internal security
  review ([Security review (2026-11)](security-audit.md), with open findings
  such as no limit on decompressed body size), but no external audit.
