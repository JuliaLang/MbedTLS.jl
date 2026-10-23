# MbedTLS

[![CI](https://github.com/JuliaLang/MbedTLS.jl/actions/workflows/ci.yml/badge.svg)](https://github.com/JuliaLang/MbedTLS.jl/actions/workflows/ci.yml)
[![codecov.io](https://codecov.io/github/JuliaLang/MbedTLS.jl/coverage.svg?branch=master)](https://codecov.io/github/JuliaLang/MbedTLS.jl?branch=master)
[![pkgeval](https://juliahub.com/docs/MbedTLS/pkgeval.svg)](https://juliahub.com/ui/Packages/MbedTLS/bf9T0)

A wrapper around the [Mbed TLS](https://github.com/Mbed-TLS/mbedtls) TLS and cryptography C library.

It uses Mbed TLS 2.24 through 2.28 from [MbedTLS_jll.jl](https://github.com/JuliaBinaryWrappers/MbedTLS_jll.jl).

Usage:

```julia
using MbedTLS, Sockets

sock = connect("httpbin.org", 443)
ctx = MbedTLS.SSLContext()
MbedTLS.setup!(ctx, MbedTLS.SSLConfig(true))  # true: verify the server's certificate
MbedTLS.set_bio!(ctx, sock)
MbedTLS.hostname!(ctx, "httpbin.org")
MbedTLS.handshake(ctx)

write(ctx, "GET /get HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n")
response = String(read(ctx))
close(ctx)
```

Debugging with Wireshark.

MbedTLS.jl can optionally log TLS session keys in
[NSS Key Log Format](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format).

e.g.
```julia
using HTTP
using MbedTLS
c = MbedTLS.SSLConfig(true, log_secrets="/Users/sam/stuff/secret_key_log")
HTTP.get("https://httpbin.org/ip", sslconfig=c)
```

Wireshark can be configured to decrypt TLS traffic by setting the location
of the key log file under:

    Wireshark Preferences -> Protocols -> TLS; (Pre)-Master-Secret log filename.

See: https://sharkfesteurope.wireshark.org/assets/presentations17eu/15.pdf
