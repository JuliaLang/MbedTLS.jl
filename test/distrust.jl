using Test, Sockets, MbedTLS

@testset "Distrusted keys" begin
    fixtures = joinpath(@__DIR__, "emudhra")
    pem_certs(path) = [MbedTLS.crt_parse(m.match) for m in
        eachmatch(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----"s, read(path, String))]

    intermediates = pem_certs(joinpath(fixtures, "intermediates.pem"))
    expected = readlines(joinpath(fixtures, "spki-sha256.txt"))
    @test length(intermediates) == length(expected) == 16
    for (crt, hash) in zip(intermediates, expected)
        spki = MbedTLS.spki_sha256(crt.data)
        @test bytes2hex(spki) == hash
        @test spki in MbedTLS.DISTRUSTED_SPKI_SHA256
    end
    leaf = first(pem_certs(joinpath(fixtures, "dv-g3b-emudhra.we-have-a-problem.com.pem")))
    @test MbedTLS.spki_sha256(leaf.data) ∉ MbedTLS.DISTRUSTED_SPKI_SHA256

    # A real handshake against a self-signed certificate that the client trusts. It must
    # succeed, then fail once the certificate's key is distrusted.
    certfile = joinpath(@__DIR__, "clntsrvr", "test.cert")
    keyfile = joinpath(@__DIR__, "clntsrvr", "test.key")
    port, server = listenany(Sockets.localhost, 8000)
    server_task = @async for _ in 1:3
        sock = accept(server)
        ctx = MbedTLS.SSLContext()
        MbedTLS.setup!(ctx, MbedTLS.SSLConfig(certfile, keyfile))
        MbedTLS.associate!(ctx, sock)
        try
            MbedTLS.handshake!(ctx)
            eof(ctx)
        catch
        finally
            close(sock)
        end
    end
    function client_connect(verify)
        conf = MbedTLS.SSLConfig(verify)
        MbedTLS.ca_chain!(conf, MbedTLS.crt_parse_file(certfile))
        ctx = MbedTLS.SSLContext()
        MbedTLS.setup!(ctx, conf)
        MbedTLS.hostname!(ctx, "tanlt")
        MbedTLS.associate!(ctx, connect(Sockets.localhost, port))
        try
            MbedTLS.handshake!(ctx)
            return true
        finally
            close(ctx)
        end
    end

    @test client_connect(true)
    spki = MbedTLS.spki_sha256(MbedTLS.crt_parse_file(certfile).data)
    push!(MbedTLS.DISTRUSTED_SPKI_SHA256, spki)
    try
        err = try client_connect(true); nothing catch e; e end
        @test err isa Base.IOError
        @test occursin("Certificate verification failed", err.msg)
        # Turning verification off still skips every check.
        @test client_connect(false)
    finally
        delete!(MbedTLS.DISTRUSTED_SPKI_SHA256, spki)
    end
    wait(server_task)
    close(server)
end
