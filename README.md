# fasthttpc

[![CI](https://github.com/cevpy/fasthttpc/actions/workflows/ci.yml/badge.svg)](https://github.com/cevpy/fasthttpc/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/fasthttpc.svg)](https://pypi.org/project/fasthttpc/)
[![Python versions](https://img.shields.io/pypi/pyversions/fasthttpc.svg)](https://pypi.org/project/fasthttpc/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Docs](https://img.shields.io/badge/docs-mkdocs-informational.svg)](https://cevpy.github.io/fasthttpc/)

[English](README.md) | [Türkçe](README.tr.md)

A pure-Python HTTP client with its own TLS 1.3 / TLS 1.2 stack, browser
TLS and HTTP/2 fingerprint impersonation (Chrome, Firefox, Safari), HTTP/2
multiplexing, and a synchronous and an asyncio API. No C extension of its own:
the only compiled dependency is [`cryptography`](https://cryptography.io) for
primitives (AEAD, X25519, certificate parsing).

> **Status: experimental (alpha).** The TLS stack is written from scratch and
> has **not** been independently security-audited. For critical production
> traffic prefer a mature client such as `curl_cffi`, `httpx` or `requests`.
> See [Security model](#security-model) and [Known limits](#known-limits).

## Install

```bash
pip install fasthttpc
pip install "fasthttpc[brotli,zstd]"   # optional content decoders
```

Python 3.10 - 3.13 on Linux, macOS and Windows.

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
| Protocols | HTTP/1.1 (keep-alive, chunked), HTTP/2 (multiplexing, flow control, GOAWAY), WebSocket (`ws://`, `wss://`) |
| TLS | Own TLS 1.3 (HelloRetryRequest, key_share x25519/secp256r1/secp384r1) and a safe subset of TLS 1.2 (ECDHE + AEAD, EMS required) |
| Server authentication | Chain + hostname, CertificateVerify, Finished, all mandatory; `verify=` custom CA bundle |
| Fingerprints | `chrome_131`, `firefox_133`, `safari_18` profiles: ClientHello (JA3/JA4), HTTP/2 SETTINGS, pseudo-header order, header order |
| Async | `AsyncSession` with the same fingerprinting and real HTTP/2 multiplexing |
| Proxies | HTTP CONNECT (+Basic), SOCKS5 (RFC 1929), rotation; TLS always terminates inside the tunnel |
| Timeouts / limits / retries | `Timeout`, `Limits`, urllib3-style `Retry` with `Retry-After` |
| Cookies, cache, redirects | RFC 6265 cookie jar, response cache, redirect history |
| DNS | Optional DNS-over-HTTPS resolver |
| Testing | `MockTransport` (sync and async handlers) |
| Typing | Ships `py.typed` |

## How it compares

Honest comparison; "maturity" matters as much as features here.

| | fasthttpc | requests | httpx | curl_cffi |
|---|---|---|---|---|
| Implementation | Pure Python + `cryptography` | Pure Python + urllib3 + `ssl` | Pure Python + h11/h2 + `ssl` | libcurl-impersonate (C) via cffi |
| TLS library | **Own TLS 1.3/1.2 code** | OpenSSL via `ssl` | OpenSSL via `ssl` | BoringSSL |
| Browser TLS/JA3/JA4 impersonation | Yes (3 families) | No | No | Yes (many versions, best coverage) |
| HTTP/2 fingerprint | Yes | No | No | Yes |
| HTTP/2 | Yes | No | Yes | Yes |
| HTTP/3 | Not yet | No | No | Yes |
| Async | Yes (asyncio) | No | Yes (asyncio, trio via anyio) | Yes |
| `verify=False` | **Not supported by design** | Yes | Yes | Yes |
| Session resumption / 0-RTT | No | Yes (OpenSSL) | Yes (OpenSSL) | Yes |
| Post-quantum key exchange | No | via OpenSSL 3.5+ | via OpenSSL 3.5+ | Yes |
| Maturity / production use | **Alpha, young, no external audit** | Very mature | Mature | Mature |
| Years of real-world hardening | None | >10 | >5 | Several |
| Speed | Pure Python: slower on bulk transfers | Fast enough | Fast enough | Fastest |

Choose fasthttpc if you want a dependency-light, readable, inspectable client
whose TLS fingerprint you can control precisely, or you cannot ship C
extensions. Choose `curl_cffi` if you need the widest and most up-to-date
fingerprint coverage or maximum performance. Choose `requests`/`httpx` when
you do not need impersonation.

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
DHE and SHA-1 signatures.

What this does **not** give you: an independent audit, constant-time
guarantees beyond what `cryptography` provides, or protection from
implementation bugs in a young protocol stack. Report vulnerabilities privately
via GitHub security advisories.

## Known limits

- No session resumption (PSK) and no 0-RTT: every connection does a full handshake.
- No post-quantum / hybrid key shares (X25519MLKEM768), no secp521r1/ffdhe.
- TLS 1.2: only ECDHE + AES-GCM / ChaCha20-Poly1305; CBC and older suites are rejected with an explicit error.
- HPACK Huffman *encoding* is not implemented (decoding is); this causes a tiny HTTP/2 fingerprint deviation.
- HTTP/2 server push is a protocol error (`ENABLE_PUSH=0`); PRIORITY is not sent.
- `Session` is not thread-safe: use one per thread.
- `Timeout.write` is not enforced separately on the sync side.
- Only 3 browser families are modelled; profiles are snapshots and age.
- Pure-Python crypto framing is slower than OpenSSL for large bulk transfers.

The full, detailed list is in [README.tr.md](README.tr.md) and the
[documentation](https://cevpy.github.io/fasthttpc/).

## Documentation

Quick start, async usage, profiles, proxies, TLS, HTTP/2, testing, migration
guides and the API reference live at <https://cevpy.github.io/fasthttpc/>
(sources in [`docs/`](docs/)).

## Development

```bash
git clone https://github.com/cevpy/fasthttpc && cd fasthttpc
pip install -e ".[dev]"
pytest            # offline unit tests
ruff check .
mypy
mkdocs serve      # needs: pip install -e ".[docs]"
```

## License

MIT. See [LICENSE](LICENSE).
