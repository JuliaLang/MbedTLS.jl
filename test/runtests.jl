using MbedTLS
using Base.Test

# Message digests
@test digest(MD_SHA256, "test", "secret") ==
   UInt8[0x03, 0x29, 0xa0, 0x6b, 0x62, 0xcd, 0x16, 0xb3, 0x3e, 0xb6, 0x79, 0x2b, 0xe8, 0xc6, 0x0b, 0x15, 0x8d, 0x89, 0xa2, 0xee, 0x3a, 0x87, 0x6f, 0xce, 0x9a, 0x88, 0x1e, 0xbb, 0x48, 0x8c, 0x09, 0x14]

# Symmetric encryption
let
    secret_key = rand(UInt8, 32)
    message = "Testing symmetric encryption"
    iv  = rand(UInt8, 16)

    cipher_text = encrypt(CIPHER_AES, secret_key, message, iv)
    plain_text = decrypt(CIPHER_AES, secret_key, cipher_text, iv)

    @test message == bytestring(plain_text)
end

# RSA
let
    key = MbedTLS.gen_key(MersenneTwister(0))
    # todo: test encryption/decryption
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
    buf = bytestring(read(ctx, 100))
    @test ismatch(r"^HTTP/1.1 200 OK", buf)
end
