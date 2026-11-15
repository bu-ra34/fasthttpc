# HTTP/3

!!! info "Status: in development"
    This page is a skeleton and is being filled in as the feature lands.
    Names below follow the current plan and may change before release.

TODO: the `http3=` flag, the `fasthttpc[http3]` extra, QUIC/UDP requirements, fallback behaviour.

## Testing against real servers

The offline suite uses a local aioquic server. To check HTTP/3 against public
servers (Alt-Svc discovery, fallback, certificate verification), see
[Live HTTP/3 tests](../testing.md#live-http3-tests).

## Server GOAWAY

A server's HTTP/3 GOAWAY marks the connection as not reusable; requests the
server did not process are retried once on a new connection. aioquic before 1.8
(the newest release for Python 3.10 is 1.3) drops GOAWAY frames, so fasthttpc
parses them itself on those versions, with the same validation as aioquic 1.8.
