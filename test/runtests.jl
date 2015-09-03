using MbedTLS
using Base.Test

# Basic client functionality
let
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
    buf = bytestring(readbytes(ctx, 100))
    @test ismatch(r"^HTTP/1.1 200 OK", buf)
end
