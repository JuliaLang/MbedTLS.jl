# Run with several threads; `runtests.jl` starts it in a child process with `-t 4`.
using Test, MbedTLS, Random, Sockets

@testset "threads" begin
    @test Threads.nthreads() > 1

    # Draws from one generator on several threads never repeat.
    rng = MbedTLS.CtrDrbg()
    MbedTLS.seed!(rng, MbedTLS.Entropy())
    draws = [Vector{Vector{UInt8}}() for _ in 1:Threads.nthreads()]
    @sync for t in 1:Threads.nthreads()
        Threads.@spawn for _ in 1:20_000
            push!(draws[t], rand(rng, 28))
        end
    end
    all_draws = reduce(vcat, draws)
    @test length(unique(all_draws)) == length(all_draws)

    # Handshakes on several threads share the server config's RSA key.
    certfile = joinpath(@__DIR__, "clntsrvr", "test.cert")
    keyfile = joinpath(@__DIR__, "clntsrvr", "test.key")
    srvrconfig = MbedTLS.SSLConfig(certfile, keyfile)
    clntconfig = MbedTLS.SSLConfig(false)
    # Reads and writes on a config that allows renegotiation also take the handshake lock.
    MbedTLS.ssl_conf_renegotiation!(clntconfig, MbedTLS.MBEDTLS_SSL_RENEGOTIATION_ENABLED)
    port, server = listenany(Sockets.localhost, 8000)
    n = 400
    acceptor = Threads.@spawn for _ in 1:n
        tcp = accept(server)
        Threads.@spawn try
            ctx = MbedTLS.SSLContext()
            MbedTLS.setup!(ctx, srvrconfig)
            MbedTLS.associate!(ctx, tcp)
            MbedTLS.handshake!(ctx)
            write(ctx, "ok")
            close(ctx)
        catch
            close(tcp)
        end
    end
    ok = Threads.Atomic{Int}(0)
    @sync for _ in 1:Threads.nthreads()
        Threads.@spawn for _ in 1:(n ÷ Threads.nthreads())
            try
                ctx = MbedTLS.SSLContext()
                MbedTLS.setup!(ctx, clntconfig)
                MbedTLS.set_bio!(ctx, connect(Sockets.localhost, port))
                MbedTLS.handshake!(ctx)
                String(read(ctx, 2)) == "ok" && Threads.atomic_add!(ok, 1)
                close(ctx)
            catch
            end
        end
    end
    wait(acceptor)
    close(server)
    @test ok[] == n
end
