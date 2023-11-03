mutable struct Entropy
    data::Ptr{Cvoid}
    sources::Vector{Any}

    function Entropy()
        ctx = new()
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
    ret = ccall((:mbedtls_entropy_add_source, libmbedcrypto), Cint,
      (Ptr{Cvoid}, Ptr{Cvoid}, Any, Csize_t, Cint),
      ctx.data, f_source, f, threshold, strong)
    Int(ret)
end

function jl_entropy(f, output, len, olen)
    output_jl = unsafe_wrap(Array, convert(Ptr{UInt8}, output), len)
    sz = f(output_jl)
    unsafe_store!(convert(Ptr{Csize_t}, olen), Csize_t(sz))
    return Cint(0)
end

function add_source!(ctx::Entropy, f::Function, threshold, strong)
    push!(ctx.sources, f)
    add_source!(ctx, c_entropy[], f, threshold, strong ? 1 : 0)
end

const c_entropy = Ref{Ptr{Cvoid}}(C_NULL)
function __entropyinit__()
    c_entropy[] = @cfunction(jl_entropy, Cint, (Any, Ptr{Cvoid}, Csize_t, Ptr{Cvoid}))
end

function gather(ctx::Entropy)
    @err_check ccall((:mbedtls_entropy_gather, libmbedcrypto), Cint,
      (Ptr{Cvoid},), ctx.data)
end

function update_manual(ctx::Entropy, data::Vector{UInt8})
    @err_check ccall((:mbedtls_entropy_update_manual, libmbedcrypto), Cint,
      (Ptr{Cvoid}, Ptr{UInt8}, Csize_t), ctx.data, data, length(data))
end
