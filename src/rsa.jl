type RSA
    data::Ptr{Void}

    function RSA(padding=MBEDTLS_RSA_PKCS_V21, hash_id=MBEDTLS_MD_MD5)
        ctx = new()
        ctx.data = Libc.malloc(1000)
        ccall((:mbedtls_rsa_init, MBED_CRYPTO), Void,
            (Ptr{Void}, Cint, Cint),
            ctx.data, padding, hash_id)
        finalizer(ctx, ctx->begin
            ccall((:mbedtls_rsa_free, MBED_CRYPTO), Void, (Ptr{Void},), ctx.data)
            Libc.free(ctx.data)
        end)
        ctx
    end
end


function gen_key!(ctx::RSA, f_rng, p_rng, nbits, exponent)
    @err_check ccall((:mbedtls_rsa_gen_key, MBED_CRYPTO), Cint,
        (Ptr{Void}, Ptr{Void}, Ptr{Void}, Cint, Cint),
        ctx.data, f_rng, p_rng, nbits, exponent)
    ctx
end


function gen_key(rng::AbstractRNG, nbits=2048, exponent=65537)
    ctx = RSA()
    gen_key!(ctx, c_rng, pointer_from_objref(rng), nbits, exponent)
    ctx
end

function public(ctx::RSA, input, output)
    @err_check ccall((:mbedtls_rsa_public, MBED_CRYPTO), Cint,
        (Ptr{Void}, Ptr{Void}, Ptr{Void}), ctx.data, input, output)
    output
end

function private(ctx::RSA, f_rng, p_rng, input, output)
    @err_check ccall((:mbedtls_rsa_private, MBED_CRYPTO), Cint,
        (Ptr{Void}, Ptr{Void}, Ptr{Void}, Ptr{Void}, Ptr{Void}),
        ctx.data, f_rng, p_rng, input, output)
    output
end

function private(ctx::RSA, rng::AbstractRNG, input, output)
    private(ctx, c_rng, pointer_from_objref(rng), input, output)
end
