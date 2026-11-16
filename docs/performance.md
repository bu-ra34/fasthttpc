# Performance

fasthttpc implements TLS, HTTP/1.1 and HTTP/2 in Python, so the per-record and
per-frame Python overhead decides the throughput of bulk transfers. This page
describes the local benchmark, what profiling showed, and what changed.

## Running the benchmark

```bash
pip install -e ".[dev]"              # h2 is needed for the HTTP/2 server
python benchmarks/local_bench.py     # all scenarios, 64 MiB bodies
python benchmarks/local_bench.py --only h2_download,h2_stream --mb 100
python benchmarks/local_bench.py --profile h2_download   # cProfile, top 25 by tottime
python benchmarks/local_bench.py --json results.json
```

Everything runs on 127.0.0.1 and needs no network. The servers run in a
**separate process**: `saha/yerel_sunucu.py` (stdlib `ssl`, TLS 1.3, HTTP/1.1)
and a small HTTP/2 server built on stdlib `ssl` and the `h2` package
(`benchmarks/_servers.py`). Certificates are verified against a throwaway CA,
the same as in the tests. Verification is never turned off.

Each scenario reports wall time and **client CPU time** (`time.process_time`
of the benchmark process, which contains only fasthttpc). The servers are also
written in Python, and for HTTP/2 they are often the slower side. Wall time is
then limited by the server, so the CPU column is the better measure of client
cost.

| Scenario | What it does |
|---|---|
| `h1_download` / `h1_chunked` | TLS 1.3 + HTTP/1.1, one large body (Content-Length / chunked) |
| `h1_stream` | same, `stream=True` + `iter_bytes()` |
| `h2_download` / `h2_stream` | TLS 1.3 + HTTP/2, one large body, read whole or streamed |
| `h1_small` / `h2_small` | 500 sequential small GETs on one keep-alive connection |
| `handshake` | 30 × (new `Session`, TCP + full TLS 1.3 handshake + one GET) |
| `async_h1` / `async_h2` | `AsyncSession`, 500 concurrent small GETs (pool of 16 / one h2 connection) |
| `async_h2_download` | `AsyncSession`, one large HTTP/2 body |

To compare against an older version, extract it and point
`FASTHTTPC_BENCH_SRC` at it:

```bash
mkdir /tmp/old && git archive v0.6.2 fasthttpc | tar -x -C /tmp/old
FASTHTTPC_BENCH_SRC=/tmp/old python benchmarks/local_bench.py
```

## What profiling showed

- **HTTP/2 receive window (largest cost).** For every 16 KiB DATA frame the
  client sent a connection WINDOW_UPDATE and a stream WINDOW_UPDATE, each in
  its own TLS record. That is two AEAD encryptions and two `sendall` calls per
  frame, about 40 % of the client's CPU time in a 64 MiB HTTP/2 download.
- **Nonce construction.** The per-record nonce was built byte by byte with a
  generator expression (12 Python steps per record, in both directions).
- **Extra copies per record.** The record payload was copied twice out of
  the read buffer (bytearray slice, then `bytes()`). It was then split into
  ciphertext and tag, and joined again for `cryptography`. On send, the result
  was split and joined again. The padding was stripped with a Python loop.
- **Small reads.** `recv(16384)` split every full-size TLS record
  (16 KiB + 22 bytes) over two system calls.
- **Debug strings in the hot loop.** The sync HTTP/2 client built
  `f"gelen frame: {frame!r}"` (an enum lookup and a format) for every frame,
  even with debugging off.
- **Frame parsing.** Each frame was copied to `bytes` and then sliced again in
  `HTTP2Frame.parse`. Whole HTTP/2 bodies were collected in a `bytearray` and
  copied once more by `bytes()`.
- **Async HTTP/2.** The reader task awaited `drain()` (through `wait_for`)
  after every frame, even when nothing had been written.
  `AsyncTLSStream.read()` returned at most one TLS record per call, even when
  several were already decrypted.
- **Small requests.** `Headers(list)` called `__setitem__` once per header, and
  each call rebuilt the whole list, which is O(n²). Every `URL` ran `parse_qs`
  even when nothing read `params`. With a `~/.netrc` file, every request parsed
  it again.
- **Handshake latency (test artifact, not a client bug).** Against the test
  server, each new connection took about 44 ms. The server does not set
  `TCP_NODELAY`, so its response after the TLS 1.3 session tickets waited for
  the client's delayed ACK (Nagle). With `TCP_NODELAY` on the server it takes
  about 2.5 ms. The benchmark server sets it, as production servers do.

## What changed

- **WINDOW_UPDATE batching.** The receive side returns credit in batches, as
  browsers do. A WINDOW_UPDATE goes out once the consumed but unreturned bytes
  reach `min(window / 2, 32 KiB)`. Chromium uses `window / 2`. The 32 KiB cap
  keeps a peer that ignores our SETTINGS and assumes a 65 535-byte window from
  stalling. Connection credit that is still owed is always returned when a
  stream ends. Credit is still only given for consumed data, so backpressure
  for streaming responses is unchanged. Connection and stream updates now go
  in **one** TLS record. With a 65 535-byte window (the `default` profile)
  updates are still sent for every DATA frame, as before. The advertised
  SETTINGS, the connection WINDOW_UPDATE in the preface and the PRIORITY
  frames do not change, so the fingerprint stays the same.
- **Record layer** (`EncryptedSocket`, the sans-IO `TLSClientConnection`, TLS
  1.2): the nonce is built with an integer XOR. `ciphertext || tag` goes
  straight to `cryptography` (new `seal`/`open` methods on the AEAD wrappers).
  The record is copied out of the read buffer once, through a `memoryview`.
  Padding is removed with `rstrip`. The sync path reads 64 KiB per `recv`. The
  security checks are the same: the AEAD tag is verified before anything is
  used, record size limits, sequence-number overflow, CCS and padding rules.
- **HTTP/2 framing:** frame fields are read straight from the buffer and the
  payload is copied once. Bodies are joined once with `b"".join`. Debug
  formatting only runs when debugging is on. The async reader task only
  drains when it has written something, and `AsyncTLSStream.read(n)` returns
  every record that is already decrypted, up to `n` bytes.
- **Small requests:** `Headers` construction is linear and the fast path of
  `__setitem__` no longer rebuilds the list. `URL.params` is parsed lazily.
  The parsed `.netrc` is cached and re-read when its mtime, size or inode
  changes.

`tests/test_perf_regresyon.py` guards the algorithmic part without timing
thresholds. It counts `recv` calls per MiB of records, TLS records per DATA
frame, and the batched credit (which must still add up to the body size). It
also checks that `Headers(list)` does not go through the quadratic
`__setitem__` path.

## Results

These were measured on the machine that ran the change: a 4-vCPU Intel Xeon
@ 2.10 GHz VM, Python 3.13.18, cryptography 50.0.1, AES-128-GCM, 64 MiB
bodies. Each cell is the client-CPU rate from the best of 5 runs (wall-clock
rate in brackets). The old and new versions were each run twice, alternating,
and both runs are shown.

| Scenario | 0.6.2 (run 1 / run 2) | this change (run 1 / run 2) |
|---|---|---|
| `h2_download` (MB/s) | 256 / 263 (251 / 252) | **477 / 438** (411 / 419) |
| `h2_stream` (MB/s) | 416 / 410 | **600 / 629** |
| `async_h2_download` (MB/s) | 232 / 225 | **327 / 367** |
| `h1_download` (MB/s) | 485 / 534 | 596 / 587 |
| `h1_chunked` (MB/s) | 454 / 492 | 544 / 515 |
| `h1_stream` (MB/s) | 1150 / 919 | 1447 / 1230 |
| `h2_small` (req/s) | 2296 / 2455 | **3461 / 3170** |
| `async_h2` (req/s) | 3374 / 3478 | 3715 / 4003 |
| `h1_small` (req/s) | 5511 / 5665 | 4602 / 5617 |
| `async_h1` (req/s) | 3672 / 2369 | 3096 / 3568 |
| `handshake` (median ms/connection) | 2.82 / 2.59 | 2.55 / 2.35 |

Caveats:

- Run-to-run noise on this shared VM is about ±15 % for the bulk scenarios and
  higher for the small-request ones. The `h1_small`, `async_h1` and `handshake`
  differences are within that noise. Their per-request cost is mostly generic
  request building, which this change barely touches.
- HTTP/2 gains the most, roughly 1.6–1.8× in CPU throughput for one large
  body. HTTP/1.1 bulk gains about 10–25 %, mostly from fewer system calls and
  copies.
- `h1_stream` runs faster than `h1_download` because reading the whole body
  ends with one `b"".join` of 64 MiB. That copy and its page faults are a
  memory cost, not a protocol cost.
- On a real network, latency and bandwidth usually dominate. These numbers
  show how much CPU the client uses per byte, not end-to-end speed against a
  remote server.
