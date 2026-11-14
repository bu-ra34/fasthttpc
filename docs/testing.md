# Testing with MockTransport

`MockTransport` skips TLS, pooling and proxies, but redirects, cookies and
retries still run exactly as in production.

```python
from fasthttpc import Session, Response, MockTransport

def handler(request):
    if request.url.path == "/login":
        return Response(200, headers={"Set-Cookie": "sid=1"})
    return Response(200, headers={"Content-Type": "application/json"}, body=b'{"ok": true}')

transport = MockTransport(handler)
with Session(transport=transport) as s:
    s.get("https://api.example.com/login")
    assert s.get("https://api.example.com/me").json() == {"ok": True}
assert len(transport.requests) == 2
```

- Exceptions raised by the handler propagate to the caller (useful to test retries).
- With `AsyncSession(transport=...)` the handler may be `async def`.
- For a custom transport subclass `fasthttpc.BaseTransport` and implement
  `handle_request(request) -> Response`.
