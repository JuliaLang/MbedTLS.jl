#  Message digest constants from mbedtls_md_type_t enum in md.h

@enum(MDKind,
      MD_NONE=0,
      MD_MD2,
      MD_MD4,
      MD_MD5,
      MD_SHA1,
      MD_SHA224,
      MD_SHA256,
      MD_SHA384,
      MD_SHA)

type MDInfo
  data::Ptr{Void}
end

type MD{IsHMAC} <: IO
    data::Ptr{Void}
    info::MDInfo

    function MD()
        ctx = new()
        ctx.data = Libc.malloc(50)  # 24
        ccall((:mbedtls_md_init, MBED_CRYPTO), Void, (Ptr{Void},), ctx.data)
        finalizer(ctx, ctx->begin
            ccall((:mbedtls_md_free, MBED_CRYPTO), Void, (Ptr{Void},), ctx.data)
            Libc.free(ctx.data)
        end)
        ctx
    end
end

function MDInfo(kind::MDKind)
    ret = ccall((:mbedtls_md_info_from_type, MBED_CRYPTO), Ptr{Void},
        (Cint,), Int(kind))
    if ret == C_NULL
        error("Could not find MD type for kind $kind")
    end
    MDInfo(ret)
end

function MDInfo(kind::AbstractString)
    ret = ccall((:mbedtls_md_info_from_string, MBED_CRYPTO), Ptr{Void},
        (Cstring,), String(kind))
    MDInfo(ret)
end

function get_name(info::MDInfo)
    ret = ccall((:mbedtls_md_get_name, MBED_CRYPTO), Ptr{UInt8},
        (Ptr{Void},), info.data)
    String(ret)
end

get_name(md::MD) = get_name(md.info)

function Base.show(io::IO, info::MDInfo)
    print(io, "Message digest $(get_name(info))")
end

function Base.show(io::IO, md::MD{true})
    print(io, "HMAC with hash $(get_name(md))")
end

function Base.show(io::IO, md::MD{false})
    print(io, "Digest with hash $(get_name(md))")
end

function MD(kind::MDKind)
    ctx = MD{false}()
    ctx.info = MDInfo(kind)
    @err_check ccall((:mbedtls_md_setup, MBED_CRYPTO), Cint,
        (Ptr{Void}, Ptr{Void}, Cint),
        ctx.data, ctx.info.data, 0)
    @err_check ccall((:mbedtls_md_starts, MBED_CRYPTO), Cint,
        (Ptr{Void},), ctx.data)
    ctx
end

function MD(kind::MDKind, key)
    ctx = MD{true}()
    ctx.info = MDInfo(kind)
    @err_check ccall((:mbedtls_md_setup, MBED_CRYPTO), Cint,
        (Ptr{Void}, Ptr{Void}, Cint),
        ctx.data, ctx.info.data, 1)
    @err_check ccall((:mbedtls_md_hmac_starts, MBED_CRYPTO), Cint,
        (Ptr{Void}, Ptr{Void}, Csize_t),
        ctx.data, pointer(key), sizeof(key))
    ctx
end

function Base.copy(md::MD)
    new_md = MD()
    @err_check ccall((:mbedtls_md_clone, MBED_CRYPTO), Cint,
        (Ptr{Void}, Ptr{Void}),
        new_md.data, md.data)
    new_md.info = md.info
    new_md
end

"""
`get_size(kind::MDKind) -> Int`

Returns the size of the digest in bytes that the given digest type requires.

For example,

```julia
get_size(MD_SHA256) == 32
```
"""
function get_size(info::MDInfo)
    ret = ccall((:mbedtls_md_get_size, MBED_CRYPTO), Cuchar,
        (Ptr{Void},), info.data)
    Int(ret)
end

get_size(md::MD) = get_size(md.info)
get_size(kind::MDKind) = get_size(MDInfo(kind))

function _write(ctx::MD{false}, buf, size)
    @err_check ccall((:mbedtls_md_update, MBED_CRYPTO), Cint,
        (Ptr{Void}, Ptr{Void}, Csize_t),
        ctx.data, buf, size)
end

function _write(ctx::MD{true}, buf, size)
    @err_check ccall((:mbedtls_md_hmac_update, MBED_CRYPTO), Cint,
        (Ptr{Void}, Ptr{Void}, Csize_t),
        ctx.data, buf, size)
end

function Base.write(ctx::MD, buf::Vector)
    isbits(eltype(buf)) || error("Expected a vector of bits types got $(typeof(buf))")
    _write(ctx, buf, sizeof(buf))
end
# To avoid ambiguity warnings
Base.write(ctx::MD, buf::Vector{UInt8}) = _write(ctx, buf, sizeof(buf))

function Base.write(ctx::MD, i::Union{Float16,Float32,Float64,Int128,Int16,Int32,Int64,UInt128,UInt16,UInt32,UInt64})
    _write(ctx, Ref(i), sizeof(i))
end
Base.write(ctx::MD, i::UInt8) = _write(ctx, Ref(i), sizeof(i))
Base.write(ctx::MD, i::Int8) = _write(ctx, Ref(i), sizeof(i))

function finish!(ctx::MD{false}, buf)
    @err_check ccall((:mbedtls_md_finish, MBED_CRYPTO), Cint,
        (Ptr{Void}, Ptr{Void}),
        ctx.data, pointer(buf))
end

function finish!(ctx::MD{true}, buf)
    @err_check ccall((:mbedtls_md_hmac_finish, MBED_CRYPTO), Cint,
        (Ptr{Void}, Ptr{Void}),
        ctx.data, pointer(buf))
end

function finish!(ctx::MD)
    buf = Array(UInt8, get_size(ctx))
    finish!(ctx, buf)
    buf
end

function digest!(kind::MDKind, msg, buf)
    msg_b = String(msg)
    @err_check ccall((:mbedtls_md, MBED_CRYPTO), Cint,
        (Ptr{Void}, Ptr{Void}, Csize_t, Ptr{Void}),
        MDInfo(kind).data, pointer(msg_b), sizeof(msg_b), pointer(buf))
end

"""
`digest(kind::MDKind, msg::Vector{UInt8}, [key::Vector{UInt8}]) -> Vector{UInt8}`

Perform a digest of the given type on the given message (a byte array),
return a byte array with the digest.

If an optional key is given, perform an HMAC digest.
"""
function digest end

"""
`digest!(kind::MDKind, msg::Vector{UInt8}, [key::Vector{UInt8}, ], buffer::Vector{UInt8})`

In-place version of `digest` that stores the digest to `buffer`.

It is the user's responsibility to ensure that buffer is long enough to contain the digest.
`get_size(kind::MDKind)` returns the appropriate size.
"""
function digest! end

function digest(kind::MDKind, msg)
    buf = Array(UInt8, get_size(kind))
    digest!(kind, msg, buf)
    buf
end

function digest!(kind::MDKind, msg, key, buf)
    msg_b = String(msg)
    @err_check ccall((:mbedtls_md_hmac, MBED_CRYPTO), Cint,
        (Ptr{Void}, Ptr{Void}, Csize_t, Ptr{Void}, Csize_t, Ptr{Void}),
        MDInfo(kind).data, pointer(key), sizeof(key),
        pointer(msg_b), sizeof(msg_b), pointer(buf))
end

function digest(kind::MDKind, msg, key)
    buf = Array(UInt8, get_size(kind))
    digest!(kind, msg, key, buf)
    buf
end
