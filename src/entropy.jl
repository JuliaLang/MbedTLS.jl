mutable struct Entropy
    data::Ptr{Void}
    sources::Vector{Any}

    function Entropy()
        ctx = new()
        ctx.data = Libc.malloc(100000)  # Exact byte count is 75088; playing it safe with some buffer
        ctx.sources = Any[]
        ccall((:mbedtls_entropy_init, MBED_CRYPTO), Void, (Ptr{Void},), ctx.data)
        finalizer(ctx, ctx->begin
            ccall((:mbedtls_entropy_free, MBED_CRYPTO), Void, (Ptr{Void},), ctx.data)
            Libc.free(ctx.data)
        end
        )
        ctx
    end
end

function add_source!(ctx::Entropy, f_source::Ptr, p_source::Ptr, threshold, strong)
    ret = ccall((:mbedtls_entropy_add_source, MBED_CRYPTO), Cint,
      (Ptr{Void}, Ptr{Void}, Ptr{Void}, Csize_t, Cint),
      ctx.data, f_source, p_source, threshold, strong)
    Int(ret)
end

function jl_entropy(data, output, len, olen)
    f = unsafe_pointer_to_objref(data)
    output_jl = unsafe_wrap(Array, convert(Ptr{UInt8}, output), len, false)
    sz = f(output_jl)
    unsafe_store!(convert(Ptr{Csize_t}, olen), Csize_t(sz))
    return Cint(0)
end

function add_source!(ctx::Entropy, f, threshold, strong)
    push!(ctx.sources, f)
    add_source!(ctx, c_entropy[], pointer_from_objref(f), threshold, strong ? 1 : 0)
end

const c_entropy = Ref{Ptr{Void}}(C_NULL)
function __entropyinit__()
    c_entropy[] = cfunction(jl_entropy, Cint, Tuple{Ptr{Void}, Ptr{Void}, Csize_t, Ptr{Void}})
end

function gather(ctx::Entropy)
    @err_check ccall((:mbedtls_entropy_gather, MBED_CRYPTO), Cint,
      (Ptr{Void},), ctx.data)
end

function update_manual(ctx::Entropy, data::Vector{UInt8})
    @err_check ccall((:mbedtls_entropy_update_manual, MBED_CRYPTO), Cint,
      (Ptr{Void}, Ptr{Void}, Csize_t), ctx.data, pointer(data), length(data))
end
