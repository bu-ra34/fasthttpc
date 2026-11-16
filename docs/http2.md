# HTTP/2

HTTP/2 is negotiated through ALPN. With `impersonate=`, the ALPN list is the
profile's (`h2, http/1.1`); if the server picks `h2` you get a real HTTP/2
connection, otherwise HTTP/1.1. The `default` profile (`impersonate=None`)
offers only `http/1.1`.

- Multiplexing: on `AsyncSession` concurrent requests share one connection
  (`asyncio.gather`). `Session` runs one request at a time on a connection.
- Flow control, SETTINGS, PING ack, RST_STREAM, GOAWAY (RFC 9113 section 6.8:
  unprocessed streams are retried on a new connection).
- Streaming responses (`stream=True`): WINDOW_UPDATE is only sent for data the
  caller has consumed.
- The SETTINGS set and order, the connection WINDOW_UPDATE, the HEADERS priority
  field, pseudo-header order and header order follow the profile.
- Server push is disabled (`ENABLE_PUSH=0`); a PUSH_PROMISE from the server is a
  connection error (GOAWAY with PROTOCOL_ERROR) on both `Session` and
  `AsyncSession`. PRIORITY frames are not sent and
  are ignored when received.
- HPACK Huffman *encoding* is not implemented (decoding is).

HTTP/1.1 keep-alive pools are keyed by `(host, port, proxy, TLS path)`.
Connections with `Connection: close`, HTTP/1.0, EOF-framed bodies, or that
errored are never returned to the pool. See also [HTTP/3](features/http3.md).
