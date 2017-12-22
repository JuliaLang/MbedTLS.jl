mutable struct PKContext
    data::Ptr{Cvoid}

    function PKContext()
        ctx = new()
        ctx.data = Libc.malloc(32)

        ccall((:mbedtls_pk_init, MBED_CRYPTO), Cvoid, (Ptr{Cvoid},), ctx.data)

        @compat finalizer(ctx->begin
            ccall((:mbedtls_pk_free, MBED_CRYPTO), Cvoid, (Ptr{Cvoid},), ctx.data)
            Libc.free(ctx.data)
        end, ctx)
        ctx
    end
end

function parse_keyfile!(ctx::PKContext, path, password="")
    @err_check ccall((:mbedtls_pk_parse_keyfile, MBED_CRYPTO), Cint,
        (Ptr{Cvoid}, Cstring, Cstring),
        ctx.data, path, password)
end

function parse_keyfile(path, password="")
    ctx = PKContext()
    parse_keyfile!(ctx, path, password)
    ctx
end

function parse_public_keyfile!(ctx::PKContext, path)
    @err_check ccall((:mbedtls_pk_parse_public_keyfile, MBED_CRYPTO), Cint,
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
    @err_check ccall((:mbedtls_pk_parse_public_key, MBED_CRYPTO), Cint,
        (Ptr{Cvoid}, Ptr{Cuchar}, Csize_t),
        ctx.data, key_bs, sizeof(key_bs) + 1)
end

@static if VERSION < v"0.7.0-DEV.3017"
parse_key!(ctx::PKContext, key, maybe_pw::Nullable) = parse_key!(ctx, key, isnull(maybe_pw) ? nothing : get(maybe_pw))
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
    @err_check ccall((:mbedtls_pk_parse_key, MBED_CRYPTO), Cint,
        (Ptr{Cvoid}, Ptr{Cuchar}, Csize_t, Ptr{Cuchar}, Csize_t),
        ctx.data, key_bs, sizeof(key_bs) + 1, pw, pw_size)
end

function bitlength(ctx::PKContext)
    sz = ccall((:mbedtls_pk_get_bitlen, MBED_CRYPTO), Csize_t,
        (Ptr{Cvoid},), ctx.data)
    sz >= 0 || mbed_err(sz)
    Int(sz)
end

function decrypt!(ctx::PKContext, input, output, rng)
    outlen_ref = Ref{Cint}(0)
    @err_check ccall((:mbedtls_pk_decrypt, MBED_CRYPTO), Cint,
        (Ptr{Cvoid}, Ptr{UInt8}, Csize_t, Ptr{Cvoid}, Ref{Cint}, Csize_t, Ptr{Cvoid}, Ptr{Cvoid}),
        ctx.data, input, sizeof(input), output, outlen_ref, sizeof(output), c_rng[], pointer_from_objref(rng))
    outlen = outlen_ref[]
    Int(outlen)
end

function encrypt!(ctx::PKContext, input, output, rng)
    outlen_ref = Ref{Cint}(0)
    @err_check ccall((:mbedtls_pk_encrypt, MBED_CRYPTO), Cint,
        (Ptr{Cvoid}, Ptr{UInt8}, Csize_t, Ptr{Cvoid}, Ref{Cint}, Csize_t, Ptr{Cvoid}, Ptr{Cvoid}),
        ctx.data, input, sizeof(input), output, outlen_ref, sizeof(output), c_rng[], pointer_from_objref(rng))
    outlen = outlen_ref[]
    Int(outlen)
end

function sign!(ctx::PKContext, hash_alg::MDKind, hash, output, rng)
    outlen_ref = Ref{Csize_t}(sizeof(output))
    @err_check ccall((:mbedtls_pk_sign, MBED_CRYPTO), Cint,
        (Ptr{Cvoid}, Cint, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Ref{Csize_t}, Ptr{Cvoid}, Ptr{Cvoid}),
        ctx.data, hash_alg, hash, sizeof(hash), output, outlen_ref, c_rng[], pointer_from_objref(rng))
    outlen = outlen_ref[]
    Int(outlen)
end

function sign(ctx::PKContext, hash_alg::MDKind, hash, rng)
    n = Int64(ceil(bitlength(ctx) / 8))
    output = Vector{UInt8}(uninitialized, n)
    @assert sign!(ctx, hash_alg, hash, output, rng) == n
    output
end

function verify(ctx::PKContext, hash_alg::MDKind, hash, signature)
    @err_check ccall((:mbedtls_pk_verify, MBED_CRYPTO), Cint,
        (Ptr{Cvoid}, Cint, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t),
        ctx.data, hash_alg, hash, sizeof(hash), signature, sizeof(signature))
end

function get_name(ctx::PKContext)
    ptr = ccall((:mbedtls_pk_get_name, MBED_CRYPTO), Ptr{Cchar}, (Ptr{Cvoid},), ctx.data)
    unsafe_string(convert(Ptr{UInt8}, ptr))
end
