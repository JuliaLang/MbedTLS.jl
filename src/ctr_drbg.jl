mutable struct CtrDrbg  <: AbstractRNG
    data::Ptr{Cvoid}
    entropy::Union{Cvoid, Entropy}

    function CtrDrbg()
        ctx = new()
        ctx.data = Libc.malloc(1000)  # 344
        ccall((:mbedtls_ctr_drbg_init, libmbedcrypto), Cvoid, (Ptr{Cvoid},), ctx.data)
        finalizer(ctx->begin
            ccall((:mbedtls_ctr_drbg_free, libmbedcrypto), Cvoid, (Ptr{Cvoid},), ctx.data)
            Libc.free(ctx.data)
        end, ctx)
        ctx
    end


    CrtDrbg(data) = new(data)
end

function f_rng(rng, c_buf, sz)
    jl_buf = unsafe_wrap(Array, c_buf, sz)
    rand!(rng, jl_buf)
    MBED_SUCCESS
end

function seed!(rng::CtrDrbg, entropy, pdata)
    rng.entropy = entropy
    entropy_func = cglobal((:mbedtls_entropy_func, libmbedcrypto))
    @err_check ccall((:mbedtls_ctr_drbg_seed, libmbedcrypto), Cint,
        (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Csize_t),
        rng.data, entropy_func, entropy.data, pdata, sizeof(pdata))
    rng
end

seed!(rng::CtrDrbg, entropy) = seed!(rng, entropy, UInt8[])

function Random.rand!(rng::CtrDrbg, buf::Array)
    @err_check ccall((:mbedtls_ctr_drbg_random, libmbedcrypto), Cint,
            (Ptr{Cvoid}, Ptr{Cvoid}, Csize_t),
        rng.data, buf, sizeof(buf))
    buf
end

function Random.rand(rng::CtrDrbg, size::Integer)
    buf = Vector{UInt8}(undef, size)
    rand!(rng, buf)
end

const c_rng = Ref{Ptr{Cvoid}}(C_NULL)
function __ctr_drbg__init__()
    c_rng[] = @cfunction(f_rng, Cint, (Any, Ptr{UInt8}, Csize_t))
end