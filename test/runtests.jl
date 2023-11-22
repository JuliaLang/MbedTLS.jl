using MbedTLS, Test, Random, Distributed

# by adding a single worker, we load the julia-shipped mbedtls binaries and thus ensure
# the rest of the MbedTLS.jl tests run propertly even in the presence of alternative
# versioned mbedtls libraries
addprocs(1)

import Sockets: connect

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

    @test message == String(plain_text)
end

# openssl rsa -inform PEM -text -noout < key.pem
# keyPEMN =
# """
#     00:bc:42:e0:e8:31:52:fd:af:e3:32:42:c4:28:5b:
#     e9:cf:50:af:e9:20:c7:96:37:5c:cb:09:e6:90:5c:
#     ac:fc:8c:03:22:7c:68:70:32:f0:7b:e4:52:85:a2:
#     12:61:ac:82:16:a6:66:e8:e9:a2:f4:dc:b7:05:0f:
#     e0:21:ea:0d:6d:0d:3e:fe:5e:c2:6a:59:36:52:c9:
#     66:5a:54:b9:f7:80:43:41:48:56:b5:b3:50:bd:2a:
#     29:8c:81:96:29:64:0a:80:82:a4:dc:93:28:8f:43:
#     d5:0b:4b:3a:4f:c4:be:a0:ff:3f:c6:68:16:f0:c5:
#     be:04:16:fc:b6:52:c4:d8:f9:4d:66:bc:d6:b8:ce:
#     4f:a4:5a:97:66:fb:5d:db:1c:e9:e6:89:ab:f6:82:
#     9e:de:93:f7:3d:b4:35:77:5e:ae:1f:67:14:29:a4:
#     00:df:7c:2c:3d:76:42:d5:76:08:ff:11:09:20:fc:
#     bd:8a:8d:d4:a9:ce:2e:35:2b:c6:d2:de:dc:ad:1b:
#     8d:01:7c:c5:32:9a:8e:c4:f7:a6:94:55:d3:4b:96:
#     1b:ee:a0:94:95:5f:b2:a0:b0:f8:bb:02:b0:a5:a9:
#     0e:62:f1:a2:8a:3a:6f:ec:c2:e9:5e:b5:73:45:cb:
#     35:86:24:07:e8:11:28:25:7d:ce:35:c0:48:ff:a0:
#     f6:13
# """
keyPEMN = 23765780372307576820243785798710539106220019827391701276528023465129289386491638200309724085345164197157471148949804917921135961746756129955755123246417065664000080083079385610461361129162124204308601470870363093163972105641380345473969785909726960802402051498557030325897388318234260665809255594699414895859065471822450027547355233222204156733689900551990147367094140650142549959621935662238290254703866686898285439063843022440258882238926771918029490099100463478790421686785230680564068945032213969236010272566088532861337469543246408184082656216674316765444657485587779489134661155841677954252447171077733538133523
keyPEMe = BigInt(65537)

function verify_key_pem(data, signature)
    pubkey = RSA(MbedTLS.MBEDTLS_RSA_PKCS_V15, MD_SHA1)
    @test_throws MbedTLS.MbedException MbedTLS.pubkey_from_vals!(pubkey, keyPEMN, keyPEMe)
    MbedTLS.pubkey_from_vals!(pubkey, keyPEMe, keyPEMN)
    MbedTLS.verify(pubkey, MD_SHA1, MbedTLS.digest(MD_SHA1, data), signature)
end

# RSA
let
    key = MbedTLS.gen_key(MersenneTwister(0))
    # todo: test encryption/decryption

    # Test signature verification.
    # Pre-generated signature of "MbedTLS.jl" using key.pem
    signature =
    UInt8[0x35,0x6d,0xa0,0xdd,0x02,0x06,0xc2,0x8e,0x21,0xcf,0x34,0x48,0x59,0x39,
          0x61,0x2c,0x37,0x50,0x74,0x2f,0x1c,0x25,0x49,0x52,0x1c,0xaf,0xb0,0xb5,
          0x2d,0x52,0x4d,0xa0,0x45,0x86,0x23,0xc8,0xf4,0xc6,0xb1,0xa2,0x25,0x86,
          0x5b,0xe6,0xcc,0x34,0x21,0xd6,0x31,0x36,0x0c,0xaf,0x97,0xa4,0x7e,0xf4,
          0xe3,0x1a,0x5f,0x58,0x78,0x57,0xbf,0x1f,0xfd,0x5e,0xe0,0xc2,0x9a,0x33,
          0x66,0xb2,0x4b,0x41,0xb2,0x37,0xac,0x63,0xd2,0x7d,0x9b,0x76,0x2f,0xe8,
          0x66,0x1e,0x83,0x4f,0x45,0x47,0x76,0x3f,0xcc,0x91,0xbb,0x8b,0xc2,0x12,
          0x8a,0x69,0x83,0x39,0xca,0x87,0xbd,0x36,0xa0,0x5e,0x21,0x60,0x39,0x9b,
          0xf0,0x3c,0x84,0x19,0x92,0xfc,0x76,0xaa,0x71,0xd8,0x39,0x0c,0x5a,0x2c,
          0x82,0xe3,0x77,0xc1,0xcc,0x7b,0xb0,0xfb,0x3f,0xb4,0x4a,0xf1,0xaa,0xa8,
          0xae,0x1e,0x46,0xde,0x42,0xc4,0x1d,0x9b,0xe9,0x58,0xaf,0x36,0xb5,0xbf,
          0x35,0x92,0x94,0x5e,0x73,0xca,0x83,0x34,0x05,0xe3,0xf5,0x8c,0x18,0x3a,
          0xb6,0xea,0xe0,0xc9,0x54,0x83,0x13,0x1f,0xd0,0x4e,0x4e,0x26,0xdb,0xec,
          0x8a,0x98,0x99,0x03,0x09,0x49,0xd5,0x10,0x2f,0xc4,0x61,0xc7,0x9d,0x5f,
          0x37,0x10,0x49,0x28,0x72,0xb5,0x43,0xba,0x96,0x98,0x2c,0xb1,0x86,0x6e,
          0x04,0x80,0x61,0xdb,0x00,0x77,0x31,0x14,0xf3,0x31,0x0e,0xc6,0xda,0x40,
          0x73,0xe7,0x3e,0x1f,0xa6,0x45,0x29,0x43,0xcb,0xe2,0xff,0x1e,0xe8,0xaa,
          0x4f,0x0b,0x01,0xcb,0x4f,0xf2,0xe4,0xc9,0xfd,0x1d,0xb8,0x5c,0x40,0xf2,
          0xeb,0x76,0x2b,0x5f]
    verify_key_pem("MbedTLS.jl", signature)
end

# Basic TLS client functionality
let
    testhost = "httpbin.org"
    sock = connect(testhost, 443)
    entropy = MbedTLS.Entropy()

    function entropy_func(buf)
        buf[:] = rand(RandomDevice(), UInt8, length(buf))
        return Cint(length(buf))
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
    MbedTLS.set_dbg_level(MbedTLS.DebugThreshold(1))

    MbedTLS.ca_chain!(conf)

    MbedTLS.setup!(ctx, conf)
    MbedTLS.set_bio!(ctx, sock)
    MbedTLS.hostname!(ctx, testhost)
    MbedTLS.handshake(ctx)

    write(ctx, "GET / HTTP/1.1\r\nHost: $testhost\r\n\r\n")
    buf = String(read(ctx, 100))
    @test occursin(r"^HTTP/1.1 200 OK", buf)
end

# Test ALPN
let
    testhost = "google.com"
    sock = connect(testhost, 443)
    entropy = MbedTLS.Entropy()

    function entropy_func(buf)
        buf[:] = rand(RandomDevice(), UInt8, length(buf))
        return Cint(length(buf))
    end

    MbedTLS.add_source!(entropy, entropy_func, 0, true)
    rng = MbedTLS.CtrDrbg()
    MbedTLS.seed!(rng, entropy)

    ctx = MbedTLS.SSLContext()
    conf = MbedTLS.SSLConfig()

    MbedTLS.config_defaults!(conf)
    MbedTLS.set_alpn!(conf, ["h2"])
    MbedTLS.authmode!(conf, MbedTLS.MBEDTLS_SSL_VERIFY_REQUIRED)
    MbedTLS.rng!(conf, rng)

    function show_debug(level, filename, number, msg)
        @show level, filename, number, msg
    end

    MbedTLS.dbg!(conf, show_debug)
    MbedTLS.set_dbg_level(MbedTLS.DebugThreshold(1))

    MbedTLS.ca_chain!(conf)

    MbedTLS.setup!(ctx, conf)
    MbedTLS.set_bio!(ctx, sock)
    MbedTLS.hostname!(ctx, testhost)
    MbedTLS.handshake(ctx)

    write(ctx, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
    @test MbedTLS.alpn_proto(ctx) == "h2"
end

# Test pk.jl methods
let
    key = MbedTLS.parse_keyfile(joinpath(@__DIR__, "key.pem"))
    @test MbedTLS.bitlength(key) == 2048
    @test MbedTLS.get_name(key) == "RSA"
    output = fill(0x00, 256)
    @test sizeof(output) == MbedTLS.sign!(key, MD_SHA1,
        MbedTLS.digest(MD_SHA1, "MbedTLS.jl"), output, MersenneTwister(0))
    verify_key_pem("MbedTLS.jl", output)

    signature = MbedTLS.sign(key, MD_SHA1,
        MbedTLS.digest(MD_SHA1, "MbedTLS.jl"), MersenneTwister(0))
    @test signature == output[1:length(signature)]

    key_string = read(open(joinpath(@__DIR__, "key.pem"), "r"))
    key = MbedTLS.PKContext()
    MbedTLS.parse_key!(key, key_string)
    @test MbedTLS.bitlength(key) == 2048
    @test MbedTLS.get_name(key) == "RSA"

    pubkey_string = read(open(joinpath(@__DIR__, "public_key.pem"), "r"))
    pubkey = MbedTLS.PKContext()
    MbedTLS.parse_public_key!(pubkey, pubkey_string)
    @test MbedTLS.bitlength(pubkey) == 2048
    @test MbedTLS.get_name(pubkey) == "RSA"

    key = MbedTLS.parse_keyfile(joinpath(@__DIR__, "key.pem"))
    @test MbedTLS.bitlength(key) == 2048
    @test MbedTLS.get_name(key) == "RSA"

    pubkey = MbedTLS.parse_public_keyfile(joinpath(@__DIR__, "public_key.pem"))
    @test MbedTLS.bitlength(pubkey) == 2048
    @test MbedTLS.get_name(pubkey) == "RSA"

    for md in instances(MbedTLS.MDKind)
        if in(md, (MD_NONE, MD_MD2, MD_MD4))
            continue
        end
        hash = MbedTLS.digest(md, "MbedTLS.jl")
        signature = MbedTLS.sign(key, md, hash, MersenneTwister(0))
        @test MbedTLS.verify(pubkey, md, hash, signature) == 0
    end
end

# Test md.jl
let
    md = MbedTLS.MD(MD_SHA1)
    write(md, UInt8['M', 'b', 'e', 'd'])
    a32 = fill(UInt32(0), 1)
    reinterpret(UInt8, a32) .= UInt8['T', 'L', 'S', '.']
    write(md, a32[])
    a16 = fill(UInt16(0), 1)
    reinterpret(UInt8, a16) .= UInt8['j', 'l']
    write(md, a16)
    @test MbedTLS.finish!(md) == MbedTLS.digest(MD_SHA1,b"MbedTLS.jl")

    # Test reset functionality
    md = MbedTLS.MD(MbedTLS.MD_SHA256, "passcode")
    write(md, "msg")
    digest1 = MbedTLS.finish!(md)
    MbedTLS.reset!(md)
    write(md, "msg")
    digest2 = MbedTLS.finish!(md)
    @test digest1 == digest2
    write(md, "msg")
    digest3 = MbedTLS.finish!(md)
    @test digest1 ≠ digest3
end

# log_secrets
mktempdir() do d

    f = joinpath(d, "secrets.log")

    testhost = "httpbin.org"
    sock = connect(testhost, 443)

    ctx = MbedTLS.SSLContext()
    conf = MbedTLS.SSLConfig(true; log_secrets=f)

    MbedTLS.setup!(ctx, conf)
    MbedTLS.set_bio!(ctx, sock)
    MbedTLS.hostname!(ctx, testhost)
    MbedTLS.handshake(ctx)

    write(ctx, "GET / HTTP/1.1\r\nHost: $testhost\r\n\r\n")
    buf = String(read(ctx, 100))
    @test occursin(r"^HTTP/1.1 200 OK", buf)
    @test occursin(r"^CLIENT_RANDOM [0-9a-f]{64} [0-9a-f]{96}$", read(f, String))
end

# Unit test for MBedTLS errorshow (#274)
let buf = IOBuffer()
    Base.display_error(buf, try MbedTLS.mbed_err(1); catch err; err; end, nothing)
    @test occursin("Generic error", String(take!(buf)))
end

let
    include("clntsrvr/clntsrvr.jl")
end
