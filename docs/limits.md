# Known limits

- No session resumption (PSK) and no 0-RTT.
- No hybrid post-quantum key shares, secp521r1 or ffdhe.
- TLS 1.2: ECDHE + AEAD only; CBC/static RSA/DHE/PSK rejected.
- HPACK Huffman encoding missing (small HTTP/2 fingerprint deviation).
- HTTP/2 push is a protocol error; PRIORITY not sent.
- `Session` is not thread-safe.
- `Timeout.write` is not enforced separately on the sync side.
- `https://` proxies are not supported.
- Three browser families are modelled; profiles age.
- Pure-Python framing is slower than OpenSSL for bulk transfers.
- Young project: no external audit, small user base.
