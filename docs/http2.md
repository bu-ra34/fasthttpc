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
- HPACK header compression is encoded the way the profile's browser does it
  (see below), with a dynamic table per connection.

## HPACK header compression

RFC 7541 leaves the encoder a lot of freedom: when to Huffman-code a string,
which header fields go into the dynamic table, which table index a literal
refers to for its name, whether the `Cookie` header is split, and when a dynamic
table size update is written. Each browser makes different choices, and they
decide the exact bytes of every HEADERS frame. fasthttpc models them as a
per-profile policy (`PROFILES[name]["h2"]["hpack"]`, fields documented on
`fasthttpc.protocol.http2_parser.HpackPolicy`):

| Choice | Chrome (`chrome_*`, also `default`) | Firefox (`firefox_*`) | Safari (`safari_*`) |
|---|---|---|---|
| Huffman | only when strictly shorter than the raw string | always, even when longer | only when strictly shorter (assumed) |
| Added to the dynamic table | every header except pseudo-headers other than `:authority` | every header except `:path`; entries larger than half the table, or any entry when the table is smaller than 128 bytes, are not added | like Chrome (assumed) |
| Exact match in a table | indexed field (1+ byte) | indexed field, except `:path` (always a literal) and never-indexed fields | like Chrome (assumed) |
| Name reference of a literal | first static entry with the name, else the newest dynamic one | last name match when scanning static then dynamic (newest to oldest): `:path /foo` refers to index 5, a second `cookie` crumb to the oldest dynamic `cookie` entry | like Chrome (assumed) |
| Never-indexed literals (`0x10`) | none | `authorization`, cookie crumbs shorter than 20 bytes | none (assumed) |
| `Cookie` splitting (RFC 9113 §8.2.3) | trim spaces/tabs, split at every `;`, drop one following space | split at `"; "` | not split (assumed) |
| Table size update after the server's `SETTINGS_HEADER_TABLE_SIZE` | only if the value differs from the current one | on every such setting, even the same value | like Chrome (assumed) |

Sources: Chromium/QUICHE `quiche/http2/hpack/hpack_encoder.cc`,
`hpack_header_table.cc` and `hpack_static_table.cc`, Chromium
`net/spdy/spdy_session.cc`; Firefox `netwerk/protocol/http/Http2Compression.cpp`
and `Http2Session.cpp`. Chrome's output was cross-checked against published byte
captures of Chrome 151 (for example `:path /fi/matkat` =
`04 87 62533148d3d469`, `cookie: alpha=one` = `60 87 1d15ce380f517f`, a 65536-byte
table size update = `3f e1 ff 03`). Safari's network stack (CFNetwork) is closed
source: a Safari 26.6.1 capture's 277-byte HEADERS payload confirms that it
Huffman-codes and adds regular headers to the dynamic table; everything marked
"assumed" is not verified (see [Limits](limits.md#browser-fingerprint-deviations)).

Dynamic table and table size:

- The encoder is per connection and stays in step with the server's decoder:
  header blocks are encoded exactly once, in the order they go on the wire. On
  `AsyncSession` concurrent streams are encoded and written without an `await`
  in between, so block order and wire order are always the same.
- The table starts at 4096 bytes. When the server sends
  `SETTINGS_HEADER_TABLE_SIZE`, the new limit applies at once (entries are
  evicted if needed) and the next header block starts with the dynamic table size
  update: first the smallest size seen in between (if it is smaller), then the
  current one (RFC 7541 §4.2). The first request of a connection usually goes out
  before the server's SETTINGS arrive, so it never carries one, as in the
  browsers.
- A table size the server advertises above 16 MiB is capped at 16 MiB (memory
  bound); real servers advertise 4096 or 65536.
- Repeated headers cost one byte per field from the second request on a
  connection. A typical Chrome navigation request is about 480 bytes on a new
  connection and about 30 bytes when repeated on the same connection.

HTTP/1.1 keep-alive pools are keyed by `(host, port, proxy, TLS path)`.
Connections with `Connection: close`, HTTP/1.0, EOF-framed bodies, or that
errored are never returned to the pool. See also [HTTP/3](features/http3.md).
