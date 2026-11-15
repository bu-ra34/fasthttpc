# API reference

## Sessions

::: fasthttpc.Session
    options:
      members: [request, get, post, put, patch, delete, head, options, stream, close, use, pre_warm, pool_stats, set_proxies, cookies, websocket]

::: fasthttpc.AsyncSession
    options:
      members: [request, get, post, put, patch, delete, head, options, stream, gather, close, use, pre_warm, pool_stats, set_proxies, cookies, websocket, ws_connect]

## Models

::: fasthttpc.Response
::: fasthttpc.HTTPStatusError
::: fasthttpc.Request
::: fasthttpc.Headers
::: fasthttpc.URL

## Configuration

::: fasthttpc.Timeout
::: fasthttpc.Limits
::: fasthttpc.Retry
::: fasthttpc.http3.Http3Options

## Authentication

::: fasthttpc.Auth
::: fasthttpc.BasicAuth
::: fasthttpc.BearerAuth
::: fasthttpc.DigestAuth

## Client certificates

::: fasthttpc.security.client_cert.ClientCert
    options:
      members: [from_pem, from_pkcs12, coerce, close]

## Testing

::: fasthttpc.MockTransport
::: fasthttpc.BaseTransport

## Cookies, cache, metrics

::: fasthttpc.CookieJar
::: fasthttpc.Cookie
::: fasthttpc.ResponseCache
::: fasthttpc.RequestMetrics

## Plugins

::: fasthttpc.Plugin
::: fasthttpc.RetryPlugin
::: fasthttpc.RateLimitPlugin
::: fasthttpc.LoggingPlugin
::: fasthttpc.ProxyRotator

## Fingerprints and DNS

::: fasthttpc.get_profile
::: fasthttpc.available_profiles
::: fasthttpc.ja3_for_profile
::: fasthttpc.ja3_from_client_hello
::: fasthttpc.DoHResolver
::: fasthttpc.enable_debug_logging
