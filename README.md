# MbedTLS

[![Build Status](https://travis-ci.org/JuliaWeb/MbedTLS.jl.svg?branch=master)](https://travis-ci.org/JuliaWeb/MbedTLS.jl)
[![codecov.io](http://codecov.io/github/JuliaWeb/MbedTLS.jl/coverage.svg?branch=master)](http://codecov.io/github/JuliaWeb/MbedTLS.jl?branch=master)
[![MbedTLS](http://pkg.julialang.org/badges/MbedTLS_0.4.svg)](http://pkg.julialang.org/?pkg=MbedTLS&ver=0.4)

A wrapper around the [mbed](https://tls.mbed.org/) TLS and cryptography C libary.

Usage:

```julia
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
buf = bytestring(read(ctx, 100))
@test ismatch(r"^HTTP/1.1 200 OK", buf)
```
