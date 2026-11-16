# Profiles and fingerprints

`impersonate=` selects a browser profile that controls the **TLS ClientHello**
(cipher suites, extensions and their order, groups, ALPN), the **HTTP/2
fingerprint** (SETTINGS, window updates, HEADERS priority, pseudo-header order)
and default **headers and header order**. The default is `"chrome_131"` for
both `Session` and `AsyncSession`.

| Profile | Aliases |
|---|---|
| `chrome_131` | `chrome` |
| `firefox_133` | `firefox`, `firefox_120` |
| `safari_18` | `safari`, `safari_17` |
| `default` | none (no browser impersonation; select it with `impersonate=None`) |

An unknown name raises `ValueError`; it never silently falls back to `default`.

`impersonate=None` behaves differently in the two clients: `Session` still uses
fasthttpc's own TLS stack with the plain `default` profile (ALPN `http/1.1`),
while `AsyncSession` uses Python's `ssl` module (HTTP/1.1 only, no `cert=`).

```python
from fasthttpc import Session, available_profiles, get_profile, ja3_for_profile

print(available_profiles())
ja3_str, ja3_hash = ja3_for_profile("chrome_131")
```

`ja3_for_profile()` does not read the profile dictionary: it builds a real
ClientHello and parses the bytes that would go on the wire.

## Key exchange groups

| Profile | key_share sent | Also advertised in `supported_groups` |
|---|---|---|
| `chrome_131` | GREASE, X25519MLKEM768\*, x25519 | secp256r1, secp384r1 |
| `firefox_133` | X25519MLKEM768\*, x25519, secp256r1 | secp384r1, secp521r1, ffdhe2048, ffdhe3072 |
| `safari_18` | GREASE, x25519 | secp256r1, secp384r1, secp521r1 |
| `default` | x25519 | secp256r1, secp384r1 |

\* Only when the installed `cryptography` provides ML-KEM (version 47 or
newer). Otherwise X25519MLKEM768 is removed from both `supported_groups` and
key_share, and the ClientHello no longer matches the real browser.
fasthttpc cannot do secp521r1 or ffdhe key exchange: they are advertised only
for the fingerprint, and a HelloRetryRequest asking for one fails with an
explicit error.

## HTTP/3

Over HTTP/3 the TLS handshake is performed by aioquic, so the browser
ClientHello is **not** reproduced there. Only the QUIC transport parameters and
HTTP/3 SETTINGS follow a profile, and only the Chrome family has one (other
profiles use aioquic defaults). See [HTTP/3](features/http3.md).

!!! info "Honest caveats"
    Profiles are snapshots of specific browser versions and age as browsers
    change. Not implemented: HPACK Huffman *encoding* (small HTTP/2 deviation),
    secp521r1/ffdhe key exchange. Post-quantum X25519MLKEM768 depends on the
    `cryptography` version. `legacy_tls=True` appends old suites and changes the
    ClientHello. Session resumption is off by default; when turned on, resumed
    connections add a `pre_shared_key` extension. Anti-bot systems may
    fingerprint more than TLS and HTTP/2.
