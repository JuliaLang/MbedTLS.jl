mutable struct CtrDrbg  <: AbstractRNG
    data::Ptr{Cvoid}
    entropy::Union{Cvoid, Entropy}
    # MbedTLS_jll is built without `MBEDTLS_THREADING_C`, so the C context has no mutex, and
    # every `SSLContext` set up with an `SSLConfig` draws from the config's generator.
    lock::ReentrantLock

    function CtrDrbg()
        ctx = new()
        ctx.lock = ReentrantLock()
        ctx.data = Libc.malloc(1000)  # 344
        ccall((:mbedtls_ctr_drbg_init, libmbedcrypto), Cvoid, (Ptr{Cvoid},), ctx.data)
        finalizer(ctx->begin
            ccall((:mbedtls_ctr_drbg_free, libmbedcrypto), Cvoid, (Ptr{Cvoid},), ctx.data)
            Libc.free(ctx.data)
        end, ctx)
        ctx
    end
end

function f_rng(rng, c_buf, sz)
    jl_buf = unsafe_wrap(Array, c_buf, sz)
    rand!(rng, jl_buf)
    MBED_SUCCESS
end

function seed!(rng::CtrDrbg, entropy, pdata)
    entropy_func = cglobal((:mbedtls_entropy_func, libmbedcrypto))
    Base.@lock rng.lock @err_check ccall((:mbedtls_ctr_drbg_seed, libmbedcrypto), Cint,
        (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Csize_t),
        rng.data, entropy_func, entropy.data, pdata, sizeof(pdata))
    # mbedtls keeps `entropy.data`; this also marks `rng` as seeded.
    rng.entropy = entropy
    rng
end

seed!(rng::CtrDrbg, entropy) = seed!(rng, entropy, UInt8[])

# Fill `nbytes` bytes at `ptr`, at most `MBEDTLS_CTR_DRBG_MAX_REQUEST` bytes per call.
function random!(rng::CtrDrbg, ptr::Ptr{UInt8}, nbytes::Integer)
    # mbedtls crashes when it generates from a context that was never seeded.
    isdefined(rng, :entropy) ||
        throw(ArgumentError("a `CtrDrbg` must be seeded with `MbedTLS.seed!` before use"))
    Base.@lock rng.lock while nbytes > 0
        n = min(nbytes, MBEDTLS_CTR_DRBG_MAX_REQUEST)
        @err_check ccall((:mbedtls_ctr_drbg_random, libmbedcrypto), Cint,
            (Ptr{Cvoid}, Ptr{UInt8}, Csize_t),
            rng.data, ptr, n)
        ptr += n
        nbytes -= n
    end
end

function Random.rand!(rng::CtrDrbg, buf::Array{<:Base.BitInteger})
    GC.@preserve buf random!(rng, Ptr{UInt8}(pointer(buf)), sizeof(buf))
    buf
end

function Random.rand(rng::CtrDrbg, ::Random.SamplerType{T}) where {T<:Base.BitInteger}
    x = Ref{T}()
    GC.@preserve x random!(rng, Ptr{UInt8}(Base.unsafe_convert(Ptr{T}, x)), sizeof(T))
    x[]
end

Random.rand(rng::CtrDrbg, ::Random.SamplerType{Bool}) = rand(rng, UInt8) % Bool
Random.rng_native_52(::CtrDrbg) = UInt64

function Random.rand(rng::CtrDrbg, size::Integer)
    buf = Vector{UInt8}(undef, size)
    rand!(rng, buf)
end

const c_rng = Ref{Ptr{Cvoid}}(C_NULL)
function __ctr_drbg__init__()
    c_rng[] = @cfunction(f_rng, Cint, (Any, Ptr{UInt8}, Csize_t))
end