# HTTP/2

HTTP/2 is negotiated through ALPN. With `impersonate=`, the ALPN list is the
profile's (`h2, http/1.1`); if the server picks `h2` you get a real HTTP/2
connection, otherwise HTTP/1.1.

- Multiplexing: concurrent requests share one connection (`asyncio.gather` on
  `AsyncSession`).
- Flow control, SETTINGS, PING ack, RST_STREAM, GOAWAY (RFC 9113 section 6.8:
  unprocessed streams are retried on a new connection).
- The SETTINGS set and order, pseudo-header order and HPACK encoding follow the
  profile.
- Server push is a protocol error (`ENABLE_PUSH=0`); PRIORITY frames are not
  sent and are ignored when received.
- HPACK Huffman *encoding* is not implemented (decoding is).

HTTP/1.1 keep-alive pools are keyed by `(host, port, proxy, TLS path)`.
Connections with `Connection: close`, HTTP/1.0, EOF-framed bodies, or that
errored are never returned to the pool. See also [HTTP/3](features/http3.md).
