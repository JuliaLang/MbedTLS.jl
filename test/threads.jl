# Run with several threads; `runtests.jl` starts it in a child process with `-t 4`.
using Test, MbedTLS, Random

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
end
