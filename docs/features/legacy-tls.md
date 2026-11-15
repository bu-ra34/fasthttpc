# Legacy TLS

!!! warning "Opt-in, weaker security"
    `legacy_tls` is **off by default**. Enable it only to talk to old servers
    you cannot upgrade.

```python
from fasthttpc import Session

with Session(legacy_tls=True) as s:       # AsyncSession(legacy_tls=True) works too
    r = s.get("https://old-device.local/")
    print(r.tls_info)                     # shows which weaker features were accepted
```

`legacy_tls` is a boolean parameter of `Session` / `AsyncSession` (not a profile).
It applies to fasthttpc's own TLS stack: with `AsyncSession(impersonate=None)`,
which uses Python's `ssl` module, the flag has no effect.

## What it enables (TLS 1.2 only)

- CBC suites: 0xC009, 0xC00A, 0xC013, 0xC014, 0xC023, 0xC024, 0xC027, 0xC028.
- Static RSA key exchange: 0x009C, 0x009D, 0x002F, 0x0035, 0x003C, 0x003D.
- Servers without Extended Master Secret / `renegotiation_info` are accepted
  with a warning.
- SHA-1 ServerKeyExchange signatures are accepted.

Certificate validation and `DOWNGRD` detection **keep working** unchanged.
TLS 1.0/1.1 are **not supported** (`legacy_tls="tls1.0"` raises `ValueError`):
RFC 8996 deprecates them, they have BEAST-prone implicit IVs and an MD5+SHA-1
PRF/Finished, leaving only the `DOWNGRD` check as defence.

## Trade-offs

- Static RSA has no forward secrecy.
- Without EMS, sessions are open to triple-handshake attacks.
- Lucky13 mitigation for CBC is best-effort in pure Python.
- The ClientHello fingerprint changes (EtM, SHA-1 sigalg and the old suites are
  appended), so it no longer matches the browser profile.
