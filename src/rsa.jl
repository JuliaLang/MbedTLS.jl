struct mbedtls_mpi
    s::Cint
    n::Csize_t
    p::Ptr{Cuint}
end

struct mbedtls_rsa_context
    ver::Cint
    len::Csize_t
    N::mbedtls_mpi
    E::mbedtls_mpi
    D::mbedtls_mpi
    P::mbedtls_mpi
    Q::mbedtls_mpi
    # More fields follow, but omitted here, since they
    # are not required for this wrapper
end

mutable struct RSA
    data::Ptr{mbedtls_rsa_context}

    function RSA(padding=MBEDTLS_RSA_PKCS_V21, hash_id=MD_MD5)
        ctx = new()
        ctx.data = Libc.malloc(1000)
        ccall((:mbedtls_rsa_init, libmbedcrypto), Cvoid,
            (Ptr{Cvoid}, Cint, Cint),
            ctx.data, padding, hash_id)
        finalizer(ctx->begin
            ccall((:mbedtls_rsa_free, libmbedcrypto), Cvoid, (Ptr{Cvoid},), ctx.data)
            Libc.free(ctx.data)
        end, ctx)
        ctx
    end
end

function mpi_import!(mpi::Ptr{mbedtls_mpi}, b::BigInt)
    # Export from GMP
    size = ndigits(b, base=2)
    nbytes = div(size+8-1,8)
    data = Vector{UInt8}(undef, nbytes)
    count = Ref{Csize_t}(0)
    # TODO Replace `Any` with `Ref{BigInt}` when 0.6 support is dropped.
    ccall((:__gmpz_export,:libgmp), Ptr{Cvoid},
            (Ptr{Cvoid}, Ptr{Csize_t}, Cint, Csize_t, Cint, Csize_t, Any),
            data, count, 1, 1, 1, 0, b)
    @assert count[] == nbytes
    # Import into mbedtls
    @err_check ccall((:mbedtls_mpi_read_binary, libmbedcrypto), Cint,
        (Ptr{mbedtls_mpi}, Ptr{UInt8}, Csize_t),
        mpi, data, nbytes)
end

function mpi_size(mpi::Ptr{mbedtls_mpi})
    ccall((:mbedtls_mpi_size, libmbedcrypto), Csize_t, (Ptr{mbedtls_mpi},), mpi)
end

function pubkey_from_vals!(ctx::RSA, e::BigInt, n::BigInt)
    Nptr = Ptr{mbedtls_mpi}(ctx.data+fieldoffset(mbedtls_rsa_context,3 #= :N =#))
    mpi_import!(Nptr, n)
    mpi_import!(Ptr{mbedtls_mpi}(ctx.data+fieldoffset(mbedtls_rsa_context,4 #= :E =#)), e)
    nptr_size = mpi_size(Nptr)
    unsafe_store!(Ptr{Csize_t}(ctx.data+fieldoffset(mbedtls_rsa_context,2 #=:len =#)),
        nptr_size)
    @err_check ccall((:mbedtls_rsa_check_pubkey, libmbedcrypto), Cint,
        (Ptr{Cvoid},), ctx.data)
    ctx
end

function verify(ctx::RSA, hash_alg::MDKind, hash, signature, rng = nothing; using_public=true)
    (!using_public && rng == nothing) &&
        error("Private key verification requires the rng")
    # All errors, including validation errors throw
    @err_check ccall((:mbedtls_rsa_pkcs1_verify, libmbedcrypto), Cint,
        (Ptr{Cvoid}, Ptr{Cvoid}, Any, Cint, Cint, Csize_t, Ptr{UInt8}, Ptr{UInt8}),
        ctx.data,
        rng == nothing ? C_NULL : c_rng[],
        rng == nothing ? Ref{Any}() : rng,
        using_public ? 0 : 1,
        hash_alg, sizeof(hash), hash, signature)
end


function gen_key!(ctx::RSA, f_rng, rng, nbits, exponent)
    @err_check ccall((:mbedtls_rsa_gen_key, libmbedcrypto), Cint,
        (Ptr{Cvoid}, Ptr{Cvoid}, Any, Cint, Cint),
        ctx.data, f_rng, rng, nbits, exponent)
    ctx
end


function gen_key(rng::AbstractRNG, nbits=2048, exponent=65537)
    ctx = RSA()
    gen_key!(ctx, c_rng[], rng, nbits, exponent)
    ctx
end

function public(ctx::RSA, input, output)
    @err_check ccall((:mbedtls_rsa_public, libmbedcrypto), Cint,
        (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}), ctx.data, input, output)
    output
end

function private(ctx::RSA, f_rng, rng, input, output)
    @err_check ccall((:mbedtls_rsa_private, libmbedcrypto), Cint,
        (Ptr{Cvoid}, Ptr{Cvoid}, Any, Ptr{Cvoid}, Ptr{Cvoid}),
        ctx.data, f_rng, rng, input, output)
    output
end

function private(ctx::RSA, rng::AbstractRNG, input, output)
    private(ctx, c_rng[], rng, input, output)
end
