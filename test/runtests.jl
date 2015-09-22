using MbedTLS
using Base.Test

# Hashing
let
    @test hash(MbedTLS.SHA1, "test") ==
      [169, 74, 143, 229, 204, 177, 155, 166, 28, 76, 8, 115, 211, 145, 233, 135, 152, 47, 187, 211]

    ctx = MbedTLS.MD5()
    write(ctx, UInt8[1, 2])
    write(ctx, UInt8[3, 4])
    @test MbedTLS.digest(ctx) ==
      [8, 214, 192, 90, 33, 81, 42, 121, 161, 223, 235, 157, 42, 143, 38, 47]
end

# Basic TLS client functionality
let
    testhost = "httpbin.org"
    sock = connect(testhost, 443)
    entropy = MbedTLS.Entropy()

    rng = RandomDevice()
    function entropy_func(buf)
        buf[:] = rand(rng, UInt8, length(buf))
        return length(buf)
    end

    MbedTLS.add_source!(entropy, entropy_func, 0, true)
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
    MbedTLS.hostname!(ctx, testhost)
    MbedTLS.handshake(ctx)

    write(ctx, "GET / HTTP/1.1\r\nHost: $testhost\r\n\r\n")
    buf = bytestring(readbytes(ctx, 100))
    @test ismatch(r"^HTTP/1.1 200 OK", buf)
end
