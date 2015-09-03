type Entropy
    data::Ptr{Void}

    function Entropy()
        ctx = new()
        ctx.data = Libc.malloc(2000)  # 1024
        ccall((:mbedtls_entropy_init, MBED_CRYPTO), Void, (Ptr{Void},), ctx.data)
        finalizer(ctx, ctx->begin
            ccall((:mbedtls_entropy_free, MBED_CRYPTO), Void, (Ptr{Void},), ctx.data)
            Libc.free(ctx.data)
        end
        )
        ctx
    end
end
