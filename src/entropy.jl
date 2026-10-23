mutable struct Entropy
    data::Ptr{Cvoid}
    sources::Vector{Any}
    # MbedTLS_jll is built without `MBEDTLS_THREADING_C`, so the C context has no mutex, and
    # every `CtrDrbg` seeded from this `Entropy` draws from it when it seeds and reseeds.
    lock::ReentrantLock

    function Entropy()
        ctx = new()
        ctx.lock = ReentrantLock()
        ctx.data = Libc.malloc(100000)  # Exact byte count is 75088; playing it safe with some buffer
        ctx.sources = Any[]
        ccall((:mbedtls_entropy_init, libmbedcrypto), Cvoid, (Ptr{Cvoid},), ctx.data)
        finalizer(ctx->begin
            ccall((:mbedtls_entropy_free, libmbedcrypto), Cvoid, (Ptr{Cvoid},), ctx.data)
            Libc.free(ctx.data)
        end, ctx)
        ctx
    end
end

function add_source!(ctx::Entropy, f_source::Ptr, f, threshold, strong)
    Base.@lock ctx.lock begin
        push!(ctx.sources, f)
        # Pass the stored object: mbedtls keeps this pointer, and passing `f` directly can hand
        # it a temporary box (for a closure, say) that nothing keeps alive.
        ret = ccall((:mbedtls_entropy_add_source, libmbedcrypto), Cint,
          (Ptr{Cvoid}, Ptr{Cvoid}, Any, Csize_t, Cint),
          ctx.data, f_source, ctx.sources[end], threshold, strong)
        Int(ret)
    end
end

function jl_entropy(f, output, len, olen)
    output_jl = unsafe_wrap(Array, convert(Ptr{UInt8}, output), len)
    # mbedtls reads `olen` bytes from its `len`-byte buffer.
    sz = clamp(Int(f(output_jl)), 0, Int(len))
    unsafe_store!(convert(Ptr{Csize_t}, olen), Csize_t(sz))
    return Cint(0)
end

add_source!(ctx::Entropy, f::Function, threshold, strong) =
    add_source!(ctx, c_entropy[], f, threshold, strong ? 1 : 0)

const c_entropy = Ref{Ptr{Cvoid}}(C_NULL)
function __entropyinit__()
    c_entropy[] = @cfunction(jl_entropy, Cint, (Any, Ptr{Cvoid}, Csize_t, Ptr{Cvoid}))
end

# The entropy function `mbedtls_ctr_drbg_seed` is given: `mbedtls_entropy_func`, under the lock.
function f_entropy(ctx::Entropy, buf::Ptr{UInt8}, len::Csize_t)
    Base.@lock ctx.lock ccall((:mbedtls_entropy_func, libmbedcrypto), Cint,
        (Ptr{Cvoid}, Ptr{UInt8}, Csize_t), ctx.data, buf, len)
end

function gather(ctx::Entropy)
    Base.@lock ctx.lock @err_check ccall((:mbedtls_entropy_gather, libmbedcrypto), Cint,
      (Ptr{Cvoid},), ctx.data)
end

function update_manual(ctx::Entropy, data::Vector{UInt8})
    Base.@lock ctx.lock @err_check ccall((:mbedtls_entropy_update_manual, libmbedcrypto), Cint,
      (Ptr{Cvoid}, Ptr{UInt8}, Csize_t), ctx.data, data, length(data))
end
