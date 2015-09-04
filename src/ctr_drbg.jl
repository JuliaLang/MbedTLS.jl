type CtrDrbg  <: AbstractRNG
    data::Ptr{Void}

    function CtrDrbg()
        ctx = new()
        ctx.data = Libc.malloc(1000)  # 344
        ccall((:mbedtls_ctr_drbg_init, MBED_CRYPTO), Void, (Ptr{Void},), ctx.data)
        finalizer(ctx, ctx->begin
            ccall((:mbedtls_ctr_drbg_free, MBED_CRYPTO), Void, (Ptr{Void},), ctx.data)
            Libc.free(ctx.data)
        end
        )
        ctx
    end


    CrtDrbg(data) = new(data)
end

function f_rng(c_ctx, c_buf, sz)
    jl_ctx = unsafe_pointer_to_objref(c_ctx)
    jl_buf = pointer_to_array(c_buf, sz, false)
    rand!(jl_ctx, jl_buf)
    MBED_SUCCESS
end

function seed!(rng::CtrDrbg, entropy, pdata)
    entropy_func = cglobal((:mbedtls_entropy_func, MBED_CRYPTO))
    @err_check ccall((:mbedtls_ctr_drbg_seed, MBED_CRYPTO), Cint,
        (Ptr{Void}, Ptr{Void}, Ptr{Void}, Ptr{Void}, Csize_t),
        rng.data, entropy_func, entropy.data, pdata, sizeof(pdata))
    rng
end

seed!(rng::CtrDrbg, entropy) = seed!(rng, entropy, UInt8[])

function Base.rand!(rng::CtrDrbg, buf::Array)
    @err_check ccall((:mbedtls_ctr_drbg_random, MBED_CRYPTO), Cint,
        (Ptr{Void}, Ptr{Void}, Csize_t),
        rng.data, buf, sizeof(buf))
    buf
end

function Base.rand(rng::CtrDrbg, size)
    buf = Vector{UInt8}(size)
    rand!(rng, buf)
end

function __ctr_drbg__init__()
    const global c_rng=cfunction(f_rng, Cint, (Ptr{Void}, Ptr{UInt8}, Csize_t))
end
