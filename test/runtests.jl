using Mbed
using Base.Test

# Basic client functionality
let
    sock = connect("httpbin.org", 443)
    entropy = Mbed.Entropy()
    rng = Mbed.CtrDrbg()
    Mbed.seed!(rng, entropy)

    ctx = Mbed.SSLContext()
    conf = Mbed.SSLConfig()

    Mbed.config_defaults!(conf)
    Mbed.authmode!(conf, Mbed.MBEDTLS_SSL_VERIFY_REQUIRED)
    Mbed.rng!(conf, rng)

    function show_debug(level, filename, number, msg)
        @show level, filename, number, msg
    end

    Mbed.dbg!(conf, show_debug)

    Mbed.ca_chain!(conf)

    Mbed.setup!(ctx, conf)
    Mbed.set_bio!(ctx, sock)

    Mbed.handshake(ctx)

    write(ctx, "GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n")
    buf = bytestring(readbytes(ctx, 100))
    @test ismatch(r"^HTTP/1.1 200 OK", buf)
end
