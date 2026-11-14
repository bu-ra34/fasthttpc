# Profiles and fingerprints

`impersonate=` selects a browser profile that controls the **TLS ClientHello**
(cipher suites, extensions and their order, groups, ALPN), the **HTTP/2
fingerprint** (SETTINGS, window updates, pseudo-header order) and default
**header order**.

| Profile | Aliases |
|---|---|
| `chrome_131` | `chrome` |
| `firefox_133` | `firefox`, `firefox_120` |
| `safari_18` | `safari`, `safari_17` |
| `default` | none (no browser impersonation) |

An unknown name raises `ValueError`; it never silently falls back to `default`.

```python
from fasthttpc import Session, available_profiles, get_profile, ja3_for_profile

print(available_profiles())
ja3_str, ja3_hash = ja3_for_profile("chrome_131")
```

`ja3_for_profile()` does not read the profile dictionary: it builds a real
ClientHello and parses the bytes that would go on the wire.

!!! info "Honest caveats"
    Profiles are snapshots of specific browser versions and age as browsers
    change. Not implemented: post-quantum hybrid key shares (X25519MLKEM768),
    HPACK Huffman *encoding* (small HTTP/2 deviation), session resumption.
    Anti-bot systems may fingerprint more than TLS and HTTP/2.
