# API reference

## Sessions

::: fasthttpc.Session
    options:
      members: [request, get, post, put, patch, delete, head, options, close, pre_warm, pool_stats, set_proxies, cookies, websocket]

::: fasthttpc.AsyncSession
    options:
      members: [request, get, post, put, patch, delete, head, options, gather, close, use, cookies, websocket]

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

## Testing

::: fasthttpc.MockTransport
::: fasthttpc.BaseTransport

## Cookies, cache, metrics

::: fasthttpc.CookieJar
::: fasthttpc.Cookie
::: fasthttpc.ResponseCache
::: fasthttpc.RequestMetrics

## Plugins (async)

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
