type Entropy
    data::Ptr{Void}

    function Entropy()
        ctx = new()
        ctx.data = Libc.malloc(100000)  # Exact byte count is 75088; playing it safe with some buffer
        ccall((:mbedtls_entropy_init, MBED_CRYPTO), Void, (Ptr{Void},), ctx.data)
        finalizer(ctx, ctx->begin
            ccall((:mbedtls_entropy_free, MBED_CRYPTO), Void, (Ptr{Void},), ctx.data)
            Libc.free(ctx.data)
        end
        )
        ctx
    end
end
