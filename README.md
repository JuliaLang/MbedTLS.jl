# MbedTLS

[![Build Status](https://travis-ci.org/JuliaWeb/MbedTLS.jl.svg?branch=master)](https://travis-ci.org/JuliaWeb/MbedTLS.jl)
[![codecov.io](http://codecov.io/github/JuliaWeb/MbedTLS.jl/coverage.svg?branch=master)](http://codecov.io/github/JuliaWeb/MbedTLS.jl?branch=master)
[![MbedTLS](http://pkg.julialang.org/badges/MbedTLS_0.4.svg)](http://pkg.julialang.org/?pkg=MbedTLS&ver=0.4)

A wrapper around the [mbed](https://tls.mbed.org/) TLS and cryptography C libary.

Current supported mbedtls version: 2.13.1

Usage:

```julia
using Sockets
sock = connect("httpbin.org", 443)
entropy = MbedTLS.Entropy()
rng = MbedTLS.CtrDrbg()
MbedTLS.seed!(rng, entropy)

ctx = MbedTLS.SSLContext()
conf = MbedTLS.SSLConfig()

MbedTLS.config_defaults!(conf)
MbedTLS.authmode!(conf, MbedTLS.MBEDTLS_SSL_VERIFY_REQUIRED)
MbedTLS.rng!(conf, rng)

function show_debug(level, filename, number, msg)
    @show level, filename, number, msg
end

MbedTLS.dbg!(conf, show_debug)

MbedTLS.ca_chain!(conf)

MbedTLS.setup!(ctx, conf)
MbedTLS.set_bio!(ctx, sock)

MbedTLS.handshake(ctx)

write(ctx, "GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
buf = String(read(ctx, 100))
@test ismatch(r"^HTTP/1.1 200 OK", buf)
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

Wireshark can be configrued to decrypt SSL traffic by setting the location
of the key log file under:

    Wireshark Preferences -> Protocols -> SSL; (Pre-)Master Secret log filename.

See: https://sharkfesteurope.wireshark.org/assets/presentations17eu/15.pdf
