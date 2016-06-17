type PKContext
    data::Ptr{Void}

    function PKContext()
        ctx = new()
        ctx.data = Libc.malloc(32)

        ccall((:mbedtls_pk_init, MBED_CRYPTO), Void, (Ptr{Void},), ctx.data)

        finalizer(ctx,ctx->begin
            ccall((:mbedtls_pk_free, MBED_CRYPTO), Void, (Ptr{Void},), ctx.data)
            Libc.free(ctx.data)
        end)

        ctx
    end
end

function parse_keyfile!(ctx::PKContext, path, password="")
    @err_check ccall((:mbedtls_pk_parse_keyfile, MBED_CRYPTO), Cint,
        (Ptr{Void}, Cstring, Cstring),
        ctx.data, path, password)
end

function parse_keyfile(path, password="")
    ctx = PKContext()
    parse_keyfile!(ctx, path, password)
    ctx
end

function parse_public_keyfile!(ctx::PKContext, path)
    @err_check ccall((:mbedtls_pk_parse_public_keyfile, MBED_TLS), Cint,
        (Ptr{Void}, Cstring),
        ctx.data, path)
end

function parse_key!(ctx::PKContext, key, maybe_pw::Nullable = Nullable())
    key_bs = String(key)
    if isnull(maybe_pw)
        pw = C_NULL
        pw_size = 0
    else
        pw = String(get(maybe_pw))
        pw_size = sizeof(pw)  # Might be off-by-one
    end
    @err_check ccall((:mbedtls_pk_parse_key, MBED_TLS), Cint,
        (Ptr{Void}, Ptr{Void}, Csize_t, Ptr{Void}, Csize_t),
        ctx.data, key_bs, sizeof(key_bs)+1, pw, pw_size)
end

parse_key!(ctx::PKContext, key, pw) = parse_key!(ctx, key, Nullable(pw))

function bitlength(ctx::PKContext)
    sz = ccall((:mbedtls_pk_get_bitlen, MBED_CRYPTO), Csize_t,
        (Ptr{Void},), ctx.data)
    sz >= 0 || mbed_err(sz)
    Int(sz)
end

function decrypt!(ctx::PKContext, input, output, rng)
    outlen_ref = Ref{Cint}(0)
    @err_check ccall((:mbedtls_pk_decrypt, MBED_CRYPTO), Cint,
        (Ptr{Void}, Ptr{UInt8}, Csize_t, Ptr{Void}, Ref{Cint}, Csize_t, Ptr{Void}, Ptr{Void}),
        ctx.data, input, sizeof(input), output, outlen_ref, sizeof(output), c_rng, pointer_from_objref(rng))
    outlen = outlen_ref[]
    Int(outlen)
end

function encrypt!(ctx::PKContext, input, output, rng)
    outlen_ref = Ref{Cint}(0)
    @err_check ccall((:mbedtls_pk_encrypt, MBED_CRYPTO), Cint,
        (Ptr{Void}, Ptr{UInt8}, Csize_t, Ptr{Void}, Ref{Cint}, Csize_t, Ptr{Void}, Ptr{Void}),
        ctx.data, input, sizeof(input), output, outlen_ref, sizeof(output), c_rng, pointer_from_objref(rng))
    outlen = outlen_ref[]
    Int(outlen)
end

function get_name(ctx::PKContext)
    ptr = ccall((:mbedtls_pk_get_name, MBED_CRYPTO), Ptr{Cchar}, (Ptr{Void},), ctx.data)
    unsafe_string(ptr)
end
