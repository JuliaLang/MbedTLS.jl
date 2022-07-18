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

const MBEDTLSLOCK = ReentrantLock()

function parse_keyfile!(ctx::PKContext, path, password="")
    @err_check ccall((:mbedtls_pk_parse_keyfile, libmbedcrypto), Cint,
        (Ptr{Cvoid}, Cstring, Cstring),
        ctx.data, path, password)
end

function parse_keyfile(path, password="")
    ctx = PKContext()
    parse_keyfile!(ctx, path, password)
    ctx
end

function parse_public_keyfile!(ctx::PKContext, path)
    @err_check ccall((:mbedtls_pk_parse_public_keyfile, libmbedcrypto), Cint,
        (Ptr{Cvoid}, Cstring),
        ctx.data, path)
end

function parse_public_keyfile(path)
    ctx = PKContext()
    parse_public_keyfile!(ctx, path)
    ctx
end

function parse_public_key!(ctx::PKContext, key)
    key_bs = String(key)
    @err_check ccall((:mbedtls_pk_parse_public_key, libmbedcrypto), Cint,
        (Ptr{Cvoid}, Ptr{Cuchar}, Csize_t),
        ctx.data, key_bs, sizeof(key_bs) + 1)
end

function parse_key!(ctx::PKContext, key, maybe_pw = nothing)
    key_bs = String(key)
    if maybe_pw === nothing
        pw = C_NULL
        pw_size = 0
    else
        pw = String(maybe_pw)
        pw_size = sizeof(pw)  # Might be off-by-one
    end
    @err_check ccall((:mbedtls_pk_parse_key, libmbedcrypto), Cint,
        (Ptr{Cvoid}, Ptr{Cuchar}, Csize_t, Ptr{Cuchar}, Csize_t),
        ctx.data, key_bs, sizeof(key_bs) + 1, pw, pw_size)
end

function bitlength(ctx::PKContext)
    sz = ccall((:mbedtls_pk_get_bitlen, libmbedcrypto), Csize_t,
        (Ptr{Cvoid},), ctx.data)
    sz >= 0 || mbed_err(sz)
    Int(sz)
end

function decrypt!(ctx::PKContext, input, output, rng)
    outlen_ref = Ref{Cint}(0)
    Base.@lock MBEDTLSLOCK begin
        @err_check ccall((:mbedtls_pk_decrypt, libmbedcrypto), Cint,
            (Ptr{Cvoid}, Ptr{UInt8}, Csize_t, Ptr{Cvoid}, Ref{Cint}, Csize_t, Ptr{Cvoid}, Any),
            ctx.data, input, sizeof(input), output, outlen_ref, sizeof(output), c_rng[], rng)
    end
    outlen = outlen_ref[]
    Int(outlen)
end

function encrypt!(ctx::PKContext, input, output, rng)
    outlen_ref = Ref{Cint}(0)
    Base.@lock MBEDTLSLOCK begin
        @err_check ccall((:mbedtls_pk_encrypt, libmbedcrypto), Cint,
            (Ptr{Cvoid}, Ptr{UInt8}, Csize_t, Ptr{Cvoid}, Ref{Cint}, Csize_t, Ptr{Cvoid}, Any),
            ctx.data, input, sizeof(input), output, outlen_ref, sizeof(output), c_rng[], rng)
    end
    outlen = outlen_ref[]
    Int(outlen)
end

function sign!(ctx::PKContext, hash_alg::MDKind, hash, output, rng)
    outlen_ref = Ref{Csize_t}(sizeof(output))
    Base.@lock MBEDTLSLOCK begin
        @err_check ccall((:mbedtls_pk_sign, libmbedcrypto), Cint,
                         (Ptr{Cvoid}, Cint, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Ref{Csize_t}, Ptr{Cvoid}, Any),
                         ctx.data, hash_alg, hash, sizeof(hash), output, outlen_ref, c_rng[], rng)
    end
    outlen = outlen_ref[]
    Int(outlen)
end

function sign(ctx::PKContext, hash_alg::MDKind, hash, rng)
    n = Int64(ceil(bitlength(ctx) / 8))
    output = Vector{UInt8}(undef, n)
    @assert sign!(ctx, hash_alg, hash, output, rng) == n
    output
end

function verify(ctx::PKContext, hash_alg::MDKind, hash, signature)
    @err_check ccall((:mbedtls_pk_verify, libmbedcrypto), Cint,
        (Ptr{Cvoid}, Cint, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t),
        ctx.data, hash_alg, hash, sizeof(hash), signature, sizeof(signature))
end

function get_name(ctx::PKContext)
    ptr = ccall((:mbedtls_pk_get_name, libmbedcrypto), Ptr{Cchar}, (Ptr{Cvoid},), ctx.data)
    unsafe_string(convert(Ptr{UInt8}, ptr))
end
