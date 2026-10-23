@enum(PKType,
    PK_NONE=0,
    PK_RSA,
    PK_ECKEY,
    PK_ECKEY_DH,
    PK_ECDSA,
    PK_RSA_ALT,
    PK_RSASSA_PSS,
    PK_OPAQUE)

mutable struct PKContext
    data::Ptr{Cvoid}

    function PKContext()
        ctx = new()
        ctx.data = Libc.malloc(32)

        ccall((:mbedtls_pk_init, libmbedcrypto), Cvoid, (Ptr{Cvoid},), ctx.data)

        finalizer(ctx->begin
            ccall((:mbedtls_pk_free, libmbedcrypto), Cvoid, (Ptr{Cvoid},), ctx.data)
            Libc.free(ctx.data)
        end, ctx)
        ctx
    end
end

Base.unsafe_convert(::Type{Ptr{Cvoid}}, ctx::PKContext) = ctx.data

# `String(::Vector{UInt8})` takes the vector's memory and empties it; copy the caller's bytes.
as_string(x) = x isa Vector{UInt8} ? String(copy(x)) : String(x)

function parse_keyfile!(ctx::PKContext, path, password=C_NULL)
    @err_check ccall((:mbedtls_pk_parse_keyfile, libmbedcrypto), Cint,
        (Ptr{Cvoid}, Cstring, Cstring),
        ctx, path, password)
end

function parse_keyfile(path, password=C_NULL)
    ctx = PKContext()
    parse_keyfile!(ctx, path, password)
    ctx
end

function parse_public_keyfile!(ctx::PKContext, path)
    @err_check ccall((:mbedtls_pk_parse_public_keyfile, libmbedcrypto), Cint,
        (Ptr{Cvoid}, Cstring),
        ctx, path)
end

function parse_public_keyfile(path)
    ctx = PKContext()
    parse_public_keyfile!(ctx, path)
    ctx
end

function parse_public_key!(ctx::PKContext, key)
    key_bs = as_string(key)
    @err_check ccall((:mbedtls_pk_parse_public_key, libmbedcrypto), Cint,
        (Ptr{Cvoid}, Ptr{Cuchar}, Csize_t),
        ctx, key_bs, sizeof(key_bs) + 1)
end

function parse_public_key(key)
    ctx = PKContext()
    parse_public_key!(ctx, key)
    ctx
end

function parse_key!(ctx::PKContext, key, maybe_pw = nothing)
    key_bs = as_string(key)
    if maybe_pw === nothing
        pw = C_NULL
        pw_size = 0
    else
        pw = as_string(maybe_pw)
        pw_size = sizeof(pw)
    end
    @err_check ccall((:mbedtls_pk_parse_key, libmbedcrypto), Cint,
        (Ptr{Cvoid}, Ptr{Cuchar}, Csize_t, Ptr{Cuchar}, Csize_t),
        ctx, key_bs, sizeof(key_bs) + 1, pw, pw_size)
end

function parse_key(key, maybe_pw = nothing)
    ctx = PKContext()
    parse_key!(ctx, key, maybe_pw)
    ctx
end

function bitlength(ctx::PKContext)
    sz = ccall((:mbedtls_pk_get_bitlen, libmbedcrypto), Csize_t,
        (Ptr{Cvoid},), ctx)
    sz >= 0 || mbed_err(sz)
    Int(sz)
end

function decrypt!(ctx::PKContext, input, output, rng)
    outlen_ref = Ref{Csize_t}(0)
    Base.@lock MBEDTLSLOCK begin
        @err_check ccall((:mbedtls_pk_decrypt, libmbedcrypto), Cint,
            (Ptr{Cvoid}, Ptr{UInt8}, Csize_t, Ptr{Cvoid}, Ref{Csize_t}, Csize_t, Ptr{Cvoid}, Any),
            ctx, input, sizeof(input), output, outlen_ref, sizeof(output), c_rng[], rng)
    end
    outlen = outlen_ref[]
    Int(outlen)
end

function encrypt!(ctx::PKContext, input, output, rng)
    outlen_ref = Ref{Csize_t}(0)
    Base.@lock MBEDTLSLOCK begin
        @err_check ccall((:mbedtls_pk_encrypt, libmbedcrypto), Cint,
            (Ptr{Cvoid}, Ptr{UInt8}, Csize_t, Ptr{Cvoid}, Ref{Csize_t}, Csize_t, Ptr{Cvoid}, Any),
            ctx, input, sizeof(input), output, outlen_ref, sizeof(output), c_rng[], rng)
    end
    outlen = outlen_ref[]
    Int(outlen)
end

# The most bytes `mbedtls_pk_sign` can write for `ctx`; it takes no output size.
function max_signature_size(ctx::PKContext)
    bits = bitlength(ctx)
    get_type(ctx) in (PK_ECKEY, PK_ECDSA) || return cld(bits, 8)
    # `MBEDTLS_ECDSA_MAX_SIG_LEN(bits)`: a DER sequence of two integers
    return (bits >= 61 * 8 ? 3 : 2) + 2 * ((bits >= 127 * 8 ? 3 : 2) + (bits + 8) ÷ 8)
end

function sign!(ctx::PKContext, hash_alg::MDKind, hash, output, rng)
    check_hash_size(hash_alg, hash)
    n = max_signature_size(ctx)
    sizeof(output) >= n ||
        throw(ArgumentError("signatures with this key need up to $n bytes; `output` has $(sizeof(output))"))
    outlen_ref = Ref{Csize_t}(sizeof(output))
    Base.@lock MBEDTLSLOCK begin
        @err_check ccall((:mbedtls_pk_sign, libmbedcrypto), Cint,
                         (Ptr{Cvoid}, Cint, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Ref{Csize_t}, Ptr{Cvoid}, Any),
                         ctx, hash_alg, hash, sizeof(hash), output, outlen_ref, c_rng[], rng)
    end
    outlen = outlen_ref[]
    Int(outlen)
end

function sign(ctx::PKContext, hash_alg::MDKind, hash, rng)
    output = Vector{UInt8}(undef, max_signature_size(ctx))
    resize!(output, sign!(ctx, hash_alg, hash, output, rng))
end

function verify(ctx::PKContext, hash_alg::MDKind, hash, signature)
    check_hash_size(hash_alg, hash)
    Base.@lock MBEDTLSLOCK @err_check ccall((:mbedtls_pk_verify, libmbedcrypto), Cint,
        (Ptr{Cvoid}, Cint, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t),
        ctx, hash_alg, hash, sizeof(hash), signature, sizeof(signature))
end

function get_name(ctx::PKContext)
    ptr = ccall((:mbedtls_pk_get_name, libmbedcrypto), Ptr{Cchar}, (Ptr{Cvoid},), ctx)
    unsafe_string(convert(Ptr{UInt8}, ptr))
end

function get_type(ctx::PKContext)
    ccall((:mbedtls_pk_get_type, libmbedcrypto), PKType, (Ptr{Cvoid},), ctx)
end

"""
    RSA(pk::PKContext)

The RSA key inside `pk`. It shares memory with `pk`, and keeps `pk` alive.
"""
function RSA(pk::PKContext)
    get_type(pk) == PK_RSA || throw(ArgumentError("`pk` holds a $(get_type(pk)) key, not an RSA key"))
    # We would like to do the following, but unfortunately, it's static_inline
    # in the headers.
    # ptr = ccall((:mbedtls_pk_rsa, libmbedcrypto), Ptr{mbedtls_rsa_context},
    #     (Ptr{Cvoid},), pk)
    @GC.preserve pk begin
        ptr = unsafe_load(Ptr{Ptr{mbedtls_rsa_context}}(pk.data), 2)
    end
    return RSA(ptr, pk)
end

