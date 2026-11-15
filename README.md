# fasthttpc

[![CI](https://github.com/bu-ra34/fasthttpc/actions/workflows/ci.yml/badge.svg)](https://github.com/bu-ra34/fasthttpc/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/fasthttpc.svg)](https://pypi.org/project/fasthttpc/)
[![Python versions](https://img.shields.io/pypi/pyversions/fasthttpc.svg)](https://pypi.org/project/fasthttpc/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-mkdocs-informational.svg)](https://bu-ra34.github.io/fasthttpc/)

[English](README.md) | [Türkçe](README.tr.md)

A pure-Python HTTP client with its own TLS 1.3 / TLS 1.2 stack, browser
TLS and HTTP/2 fingerprint impersonation (Chrome, Firefox, Safari), HTTP/2
multiplexing, and a synchronous and an async API (asyncio, or trio through
anyio). Experimental HTTP/3 is available as an optional extra. No C extension
of its own: the only compiled runtime dependency is
[`cryptography`](https://cryptography.io) for primitives (AEAD, X25519, ML-KEM,
certificate parsing); the optional extras (`http3`, `brotli`, `zstd`) bring
their own compiled packages.

> **Status: experimental (alpha).** The TLS stack is written from scratch. It
> has had an [internal security review](https://bu-ra34.github.io/fasthttpc/security-audit/),
> but **no independent third-party audit**. For critical production traffic
> prefer a mature client such as `curl_cffi`, `httpx` or `requests`.
> See [Security model](#security-model) and [Known limits](#known-limits).

## Install

```bash
pip install fasthttpc
pip install "fasthttpc[brotli,zstd]"   # optional content decoders
pip install "fasthttpc[trio]"          # AsyncSession under trio (anyio + trio)
pip install "fasthttpc[http3]"         # experimental HTTP/3 (aioquic)
```

Python 3.10+. CI runs the test suite on Python 3.10 - 3.13 on Linux and on
Python 3.12 on Windows and macOS.

## Quick start

```python
from fasthttpc import Session

with Session(impersonate="chrome_131") as s:
    r = s.get("https://httpbin.org/get")
    print(r.status_code, r.elapsed)
    print(r.json())
```

Async:

```python
import asyncio
from fasthttpc import AsyncSession

async def main():
    async with AsyncSession(impersonate="chrome_131") as s:
        rs = await asyncio.gather(*(s.get(f"https://httpbin.org/anything/{i}") for i in range(5)))
        print([r.status_code for r in rs])

asyncio.run(main())
```

Offline testing:

```python
from fasthttpc import Session, Response, MockTransport

transport = MockTransport(lambda request: Response(200, body=b'{"ok": true}',
                                                   headers={"Content-Type": "application/json"}))
with Session(transport=transport) as s:
    assert s.get("https://api.example.com/").json() == {"ok": True}
```

## Features

| Area | Support |
|---|---|
| Protocols | HTTP/1.1 (keep-alive, chunked), HTTP/2 (flow control, GOAWAY; concurrent streams on `AsyncSession`), WebSocket (`ws://`, `wss://`), HTTP/3 (**experimental**, opt-in, see below) |
| TLS | Own TLS 1.3 (HelloRetryRequest; key_share x25519, secp256r1, secp384r1, and hybrid post-quantum X25519MLKEM768 when `cryptography` provides ML-KEM) and a safe subset of TLS 1.2 (ECDHE + AEAD, EMS required). TLS 1.3 PSK resumption is implemented but off by default; no 0-RTT |
| Server authentication | Chain + hostname, CertificateVerify, Finished, all mandatory; `verify=` custom CA bundle |
| Client certificates | `cert=` (mTLS): PEM, encrypted PKCS#8 or PKCS#12; RSA >= 2048, P-256, P-384, Ed25519; TLS 1.3 and TLS 1.2 |
| Fingerprints | `chrome_131`, `firefox_133`, `safari_18` profiles: ClientHello (JA3/JA4), HTTP/2 SETTINGS, pseudo-header order, header order |
| Async | `AsyncSession` under asyncio, or trio through anyio (`fasthttpc[trio]`), with the same fingerprinting and real HTTP/2 multiplexing |
| Streaming | `stream=True` / `s.stream(...)`; `iter_bytes`, `iter_text`, `iter_lines`, `iter_raw` and the async `aiter_*` versions, over HTTP/1.1 and HTTP/2 |
| Auth and hooks | Basic, Digest (RFC 7616), Bearer, `.netrc`, custom auth (requests or httpx style); requests-style `hooks=`, httpx-style `event_hooks=`; plugins on `Session` and `AsyncSession` |
| Proxies | HTTP CONNECT (+Basic), SOCKS5 (RFC 1929), rotation; TLS always terminates inside the tunnel |
| Timeouts / limits / retries | `Timeout` (including a `total` budget), `Limits`, urllib3-style `Retry` with `Retry-After` |
| Cookies, cache, redirects | RFC 6265 cookie jar, response cache, redirect history |
| DNS | Optional DNS-over-HTTPS resolver; Happy Eyeballs (RFC 8305) for hosts with several addresses |
| Old servers | `legacy_tls=True` (off by default): TLS 1.2 CBC and static-RSA suites. TLS 1.0/1.1 are never supported |
| Testing | `MockTransport` (sync and async handlers) |
| Typing | Ships `py.typed` |

HTTP/3 (`http3=True`: Alt-Svc discovery with silent fallback to HTTP/2, or
`http3="force"`) is **experimental** and off by default. It needs the
`fasthttpc[http3]` extra (aioquic). The TLS handshake inside QUIC is done by
aioquic, so it does **not** carry the browser ClientHello fingerprint; only the
QUIC transport parameters and HTTP/3 SETTINGS follow a Chrome-like profile.
It has been tested against a local aioquic server only: opt-in live tests
against public servers exist (`tests/live/`), but they do not run in CI.

## How it compares

Honest comparison; "maturity" matters as much as features here.

| | fasthttpc | requests | httpx | curl_cffi |
|---|---|---|---|---|
| Implementation | Pure Python + `cryptography` | Pure Python + urllib3 + `ssl` | Pure Python + h11/h2 + `ssl` | libcurl-impersonate (C) via cffi |
| TLS library | **Own TLS 1.3/1.2 code** | OpenSSL via `ssl` | OpenSSL via `ssl` | BoringSSL |
| Browser TLS/JA3/JA4 impersonation | Yes (3 families) | No | No | Yes (many versions, best coverage) |
| HTTP/2 fingerprint | Yes | No | No | Yes |
| HTTP/2 | Yes | No | Yes | Yes |
| HTTP/3 | **Experimental**, opt-in (aioquic); no browser TLS fingerprint over QUIC; tested locally only | No | No | Yes |
| Async | Yes (asyncio, trio via anyio) | No | Yes (asyncio, trio via anyio) | Yes |
| `verify=False` | **Not supported by design** | Yes | Yes | Yes |
| Session resumption / 0-RTT | TLS 1.3 PSK resumption, **off by default**; no 0-RTT | Yes (OpenSSL) | Yes (OpenSSL) | Yes |
| Post-quantum key exchange | X25519MLKEM768 in the Chrome and Firefox profiles, only with `cryptography` >= 47; not over HTTP/3 | via OpenSSL 3.5+ | via OpenSSL 3.5+ | Yes |
| Maturity / production use | **Alpha, young; internal review only, no external audit** | Very mature | Mature | Mature |
| Years of real-world hardening | None | >10 | >5 | Several |
| Speed | Pure Python: slower on bulk transfers | Fast enough | Fast enough | Fastest |

Choose fasthttpc if you want a dependency-light, readable, inspectable client
whose TLS fingerprint you can control precisely, or you cannot ship C
extensions. Choose `curl_cffi` if you need the widest and most up-to-date
fingerprint coverage, production-grade HTTP/3 or maximum performance. Choose
`requests`/`httpx` when you do not need impersonation.

## Security model

Every TLS 1.3 connection authenticates the server with three independent
checks, all mandatory:

| Check | What it proves |
|---|---|
| Certificate chain | A trusted CA signed the certificate, hostname matches, validity period |
| **CertificateVerify** | The peer holds the certificate's **private key** (RFC 8446 section 4.4.3) |
| **Server Finished** | The handshake transcript was not tampered with (section 4.4.4) |

Trust anchors are the `certifi` bundle plus the system store, or exactly the
PEM file you pass as `verify="ca.pem"`. **`verify=False` is not supported** and
raises `ValueError`; pass the CA (or the self-signed certificate) you want to
trust instead. TLS 1.2 additionally enforces Extended Master Secret,
renegotiation_info, `DOWNGRD` sentinel detection and rejects CBC, static RSA,
DHE and SHA-1 signatures (unless you opt in with `legacy_tls=True`, which
allows CBC, static RSA, SHA-1 signatures and servers without EMS). HTTP/3
connections are checked by the same certificate validator before any request
is sent.

`AsyncSession(impersonate=None)` and the DNS-over-HTTPS resolver do not use
this stack: they use Python's `ssl` module with
`ssl.create_default_context()`, which also always verifies the certificate
chain and hostname.

What this does **not** give you: an independent audit (the internal review
and its open findings are in the
[security review](https://bu-ra34.github.io/fasthttpc/security-audit/)),
constant-time guarantees beyond what `cryptography` provides, or protection
from implementation bugs in a young protocol stack. Report vulnerabilities
privately via GitHub security advisories.

## Known limits

- TLS 1.3 PSK session resumption is implemented but **off by default**. Turn it
  on process-wide with `fasthttpc.security.session_tickets.enable_resumption(True)`
  or `FASTHTTPC_TLS_RESUMPTION=1`. There is no TLS 1.2 resumption and no 0-RTT.
- Hybrid post-quantum X25519MLKEM768 is offered only by the `chrome_131` and
  `firefox_133` profiles, and only when the installed `cryptography` provides
  ML-KEM (version 47 or newer). Otherwise the group is left out of the
  ClientHello, which then differs from the real browser's. secp521r1, x448 and
  ffdhe key exchange are not implemented.
- TLS 1.2: by default only ECDHE + AES-GCM / ChaCha20-Poly1305; CBC and static
  RSA only with `legacy_tls=True`. DHE, PSK and TLS 1.0/1.1 are always rejected
  with an explicit error.
- HPACK Huffman *encoding* is not implemented (decoding is); this causes a tiny HTTP/2 fingerprint deviation.
- HTTP/2 server push is disabled (`ENABLE_PUSH=0`). PRIORITY frames are not
  sent; the priority field of the HEADERS frame follows the profile.
- No cleartext HTTP: `http://` URLs are also fetched over TLS (on port 80
  unless the URL gives a port), so plain-HTTP-only servers cannot be reached.
  `ws://` WebSockets do use plain TCP.
- HTTP/3 is experimental: it is not used through proxies or together with
  `cert=`, does not work under trio, buffers the whole response body (also
  with `stream=True`), and never uses resumption or 0-RTT.
- `https://` proxies (TLS to the proxy) are not supported, and proxy
  environment variables (`HTTPS_PROXY`, ...) are not read.
- `Session` is not thread-safe: use one per thread.
- `Timeout.write` is not enforced separately on the sync side.
- Only 3 browser families are modelled; profiles are snapshots and age.
- Pure-Python crypto framing is slower than OpenSSL for large bulk transfers.
- Open findings of the internal review (for example no limit on the
  decompressed body size, no Public Suffix List for cookies) are listed in the
  [security review](https://bu-ra34.github.io/fasthttpc/security-audit/).

The full list is in the [documentation](https://bu-ra34.github.io/fasthttpc/limits/)
(a Turkish version is in [README.tr.md](README.tr.md)).

## Documentation

Quick start, sync and async usage, profiles, proxies, TLS, HTTP/2, HTTP/3,
streaming, auth and hooks, client certificates, trio, testing, migration
guides and the API reference live at <https://bu-ra34.github.io/fasthttpc/>
(sources in [`docs/`](docs/)).

## Development

```bash
git clone https://github.com/bu-ra34/fasthttpc && cd fasthttpc
pip install -e ".[dev]"
pytest            # offline tests; live tests are skipped unless FASTHTTPC_LIVE=1
ruff check .
mypy
mkdocs serve      # needs: pip install -e ".[docs]"
```

## License

MIT. See [LICENSE](LICENSE).
