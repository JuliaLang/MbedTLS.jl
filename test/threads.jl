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

    # Generators seeded at once from one `Entropy` on several threads get different seeds.
    entropy = MbedTLS.Entropy()
    firsts = [Vector{Vector{UInt8}}() for _ in 1:Threads.nthreads()]
    @sync for t in 1:Threads.nthreads()
        Threads.@spawn for _ in 1:5000
            r = MbedTLS.CtrDrbg()
            MbedTLS.seed!(r, entropy)
            push!(firsts[t], rand(r, 32))
        end
    end
    @test allunique(reduce(vcat, firsts))

    # Handshakes on several threads share an RSA key, through one config or two, while
    # another thread signs with it.
    certfile = joinpath(@__DIR__, "clntsrvr", "test.cert")
    keyfile = joinpath(@__DIR__, "clntsrvr", "test.key")
    srvrconfig = MbedTLS.SSLConfig(certfile, keyfile)
    srvrconfig2 = MbedTLS.SSLConfig()
    MbedTLS.config_defaults!(srvrconfig2, endpoint=MbedTLS.MBEDTLS_SSL_IS_SERVER)
    MbedTLS.rng!(srvrconfig2, srvrconfig.rng)
    MbedTLS.own_cert!(srvrconfig2, srvrconfig.cert, srvrconfig.key)
    clntconfig = MbedTLS.SSLConfig(false)
    # Reads and writes on a config that allows renegotiation also take the handshake lock.
    MbedTLS.ssl_conf_renegotiation!(clntconfig, MbedTLS.MBEDTLS_SSL_RENEGOTIATION_ENABLED)
    port, server = listenany(Sockets.localhost, 8000)
    n = 400
    acceptor = Threads.@spawn for i in 1:n
        tcp = accept(server)
        Threads.@spawn try
            ctx = MbedTLS.SSLContext()
            MbedTLS.setup!(ctx, isodd(i) ? srvrconfig : srvrconfig2)
            MbedTLS.associate!(ctx, tcp)
            MbedTLS.handshake!(ctx)
            write(ctx, "ok")
            close(ctx)
        catch
            close(tcp)
        end
    end
    hash = MbedTLS.digest(MD_SHA256, "MbedTLS.jl")
    signing = Ref(true)
    signer = Threads.@spawn begin
        nsigned = 0
        while signing[]
            MbedTLS.sign(srvrconfig.key, MD_SHA256, hash, srvrconfig.rng)
            nsigned += 1
            sleep(0.001)
        end
        nsigned
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
    signing[] = false
    @test fetch(signer) > 0
    @test ok[] == n
    # The key still works.
    signature = MbedTLS.sign(srvrconfig.key, MD_SHA256, hash, srvrconfig.rng)
    @test MbedTLS.verify(srvrconfig.key, MD_SHA256, hash, signature) == 0
end
