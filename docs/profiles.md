# Profiles and fingerprints

`impersonate=` selects a browser profile that controls the **TLS ClientHello**
(cipher suites, extensions and their order, groups, ALPN), the **HTTP/2
fingerprint** (SETTINGS, window updates, HEADERS priority, pseudo-header order)
and default **headers and header order**. The default is `"chrome_158"` for
both `Session` and `AsyncSession`.

| Profile | Browser (stable as of 2026-11-16) | Aliases |
|---|---|---|
| `chrome_158` | Chrome 158 (Windows) | `chrome` |
| `firefox_160` | Firefox 160 (Windows) | `firefox` |
| `safari_27` | Safari 27.2 (macOS) | `safari`, `safari_27_2` |
| `chrome_131` | Chrome 131 (kept for backward compatibility) | none |
| `firefox_133` | Firefox 133 (kept for backward compatibility) | `firefox_120` |
| `safari_18` | Safari 18.0 (kept for backward compatibility) | `safari_17` |
| `default` | none (no browser impersonation; select it with `impersonate=None`) | none |

An unknown name raises `ValueError`; it never silently falls back to `default`.
Up to 0.6.2 the `chrome`, `firefox` and `safari` aliases (and the `Session`
default) pointed to `chrome_131`, `firefox_133` and `safari_18`; pass those names
explicitly to keep the old fingerprints.

There is no separate Edge profile. Edge 157 uses Chromium's network stack, so its
TLS and HTTP/2 layers follow Chromium. Its User-Agent and `sec-ch-ua` brand differ.
Edge uses its own root store, and we found no capture showing whether Edge sends
the trust anchor IDs extension. To look like Edge, use `chrome_158` and override
`User-Agent` and `sec-ch-ua`. The TLS match is then unverified.

`impersonate=None` behaves differently in the two clients: `Session` still uses
fasthttpc's own TLS stack with the plain `default` profile (ALPN `http/1.1`),
while `AsyncSession` uses Python's `ssl` module (HTTP/1.1 only, no `cert=`).

```python
from fasthttpc import Session, available_profiles, get_profile, ja3_for_profile

print(available_profiles())
ja3_str, ja3_hash = ja3_for_profile("chrome_158")
```

`ja3_for_profile()` does not read the profile dictionary: it builds a real
ClientHello and parses the bytes that would go on the wire. `ja4_for_profile()`
and `akamai_h2_string()` work the same way.

## Fingerprints of the current profiles

| | `chrome_158` | `firefox_160` | `safari_27` |
|---|---|---|---|
| JA4 | `t13d1517h2_8daaf6152771_cb7bf5808d99` | `t13d1517h2_8daaf6152771_3cbfd9057e0d` | `t13d2013h2_a09f3c656075_7f0f34a4126d` |
| Akamai HTTP/2 | `1:65536;2:0;4:6291456;6:262144\|15663105\|0\|m,a,s,p` | `1:65536;2:0;4:131072;5:16384\|12517377\|0\|m,p,a,s` | `2:0;3:100;4:2097152;9:1\|10420225\|0\|m,s,a,p` |
| Extension order | permuted per connection (GREASE at both ends) | fixed | fixed |

The JA4 values assume `cryptography` with ML-KEM and ML-DSA (version 48 or newer).
With an older version the values change; see the footnotes below.

## What changed and where it comes from

**Chrome 158** (`chrome_158`, compared with `chrome_131`). Sources: Chromium
158.0.8127.37 (`net/socket/ssl_client_socket_impl.cc`, `net/base/features.cc`,
the Chrome Root Store `root_store.textproto`, `user_agent_utils.cc`); BoringSSL
`ea9f3a34` (the revision in Chromium 158's DEPS); and a local capture of a real
Google Chrome for Testing 153 ClientHello and HTTP/2 preface. With ECH GREASE off,
which was the capture condition, fasthttpc's `chrome_158` JA4 is identical to that
capture's JA4. The Chrome 158 changes:

- ALPS uses the new code point **17613** instead of 17513 (`kUseNewAlpsCodepointHttp2`
  is enabled by default). The client EncryptedExtensions message uses the same
  code point.
- New extension **51764 (0xca34) `trust_anchors`**
  ([TLS Trust Anchor IDs](https://datatracker.ietf.org/doc/draft-ietf-tls-trust-anchor-ids/)).
  It carries the 28 trust anchor IDs from the Chrome Root Store (186 bytes). Chrome
  keeps the order fixed for the life of a process, so fasthttpc shuffles it once
  per process. This extension is not post-quantum cryptography. It only helps the
  server choose a certificate chain.
- `signature_algorithms` starts with a **GREASE** value, followed by
  **ML-DSA-44/65/87** (0x0904–0x0906) and then the 8 classical schemes.
  fasthttpc really verifies ML-DSA CertificateVerify (pure ML-DSA, empty context,
  per draft-ietf-tls-mldsa) and ML-DSA certificate chains.
- `sec-ch-ua` is computed with Chromium's own GREASE-brand algorithm:
  `"Chromium";v="158", "Not.A/Brand";v="24", "Google Chrome";v="158"`.
- HTTP/2 SETTINGS, WINDOW_UPDATE, HEADERS priority, pseudo-header order and
  navigation header order are unchanged from Chrome 131 (confirmed by the capture).

**Firefox 160** (`firefox_160`, compared with `firefox_133`). Sources: Firefox
`FIREFOX_160_0_RELEASE` (NSS 3.132) source; curl-impersonate `firefox155`. The
changes:

- The ECDSA-CBC suites 0xC00A and 0xC009 are gone (15 suites).
- `ffdhe2048` and `ffdhe3072` are no longer in `supported_groups`. Firefox now adds
  them only when DHE suites are enabled, and they are disabled by default.
- ECH GREASE uses AEAD 1 or 3, and its payload length is a multiple of 32 plus 16.
- The navigation `Accept` header is
  `text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`.
- Certificate compression advertises zstd. fasthttpc now decompresses zstd when
  `zstandard` is installed.
- **No ML-DSA.** Firefox 160 lists ML-DSA in `EnabledSignatureSchemes.h`, but
  `security.tls.enable_mldsa` is `false`. That removes the SSL policy flag NSS
  requires, so ML-DSA is not in the ClientHello.

**Safari 27.2** (`safari_27`, compared with `safari_18`). Sources:
curl-impersonate `safari270` and a real Safari 26.0.1 capture; webkit.org confirms
27.2 is the current release. The changes:

- X25519MLKEM768 is in the groups and key shares.
- The TLS 1.3 suite order is 1302, 1303, 1301.
- `supported_versions` lists only TLS 1.3 and 1.2.
- 0x0203 is gone from the signature algorithms.
- HTTP/2 no longer sends SETTINGS 8 (`ENABLE_CONNECT_PROTOCOL`).
- HEADERS frames carry **no** PRIORITY flag.
- `Accept-Encoding` adds zstd, and `Upgrade-Insecure-Requests` is no longer sent.

## Key exchange groups

| Profile | key_share sent | Also advertised in `supported_groups` |
|---|---|---|
| `chrome_158`, `chrome_131` | GREASE, X25519MLKEM768\*, x25519 | secp256r1, secp384r1 |
| `firefox_160` | X25519MLKEM768\*, x25519, secp256r1 | secp384r1, secp521r1 |
| `firefox_133` | X25519MLKEM768\*, x25519, secp256r1 | secp384r1, secp521r1, ffdhe2048, ffdhe3072 |
| `safari_27` | GREASE, X25519MLKEM768\*, x25519 | secp256r1, secp384r1, secp521r1 |
| `safari_18` | GREASE, x25519 | secp256r1, secp384r1, secp521r1 |
| `default` | x25519 | secp256r1, secp384r1 |

\* Only when the installed `cryptography` provides ML-KEM (version 47 or
newer). Otherwise X25519MLKEM768 is removed from both `supported_groups` and
key_share, and the ClientHello no longer matches the real browser. Similarly,
ML-DSA signature schemes (`chrome_158`) are only advertised when `cryptography`
provides ML-DSA (version 48 or newer).
secp521r1 and ffdhe2048/3072 get no key_share in the first ClientHello, as in
the real browsers. If a server asks for one with HelloRetryRequest, fasthttpc
sends it in the second ClientHello; in TLS 1.2 an advertised secp521r1 can be
picked in ServerKeyExchange. No profile advertises x448.

## HTTP/3

Over HTTP/3 the TLS handshake is performed by aioquic, so the browser
ClientHello is **not** reproduced there. Only the QUIC transport parameters and
HTTP/3 SETTINGS follow a profile, and only the Chrome family has one (other
profiles use aioquic defaults). See [HTTP/3](features/http3.md).

!!! info "Honest caveats"
    Profiles are snapshots of specific browser versions and age as browsers
    change. Known deviations of the current profiles are listed in
    [Limits](limits.md#browser-fingerprint-deviations). Not implemented: HPACK
    Huffman *encoding* (small HTTP/2 deviation), Chrome's trust-anchor retry
    flow. Post-quantum X25519MLKEM768 and ML-DSA
    depend on the `cryptography` version. `legacy_tls=True` appends old suites
    and changes the ClientHello. Session resumption is off by default; when
    turned on, resumed connections add a `pre_shared_key` extension. Anti-bot
    systems may fingerprint more than TLS and HTTP/2.
