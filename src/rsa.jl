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

struct MPI
    ptr::Ptr{mbedtls_mpi}

    # Used for rooting only
    owner::Any
end
Base.unsafe_convert(::Type{Ptr{mbedtls_mpi}}, mpi::MPI) = mpi.ptr

mutable struct RSA
    data::Ptr{mbedtls_rsa_context}

    # Used for rooting only
    owner::Any

    function RSA(padding=MBEDTLS_RSA_PKCS_V21, hash_id=MD_MD5)
        ctx = new()
        ctx.data = Libc.malloc(1000)
        ccall((:mbedtls_rsa_init, libmbedcrypto), Cvoid,
            (Ptr{mbedtls_rsa_context}, Cint, Cint),
            ctx, padding, hash_id)
        finalizer(ctx->begin
            ccall((:mbedtls_rsa_free, libmbedcrypto), Cvoid, (Ptr{mbedtls_rsa_context},), ctx)
            Libc.free(ctx.data)
        end, ctx)
        ctx
    end

    RSA(data::Ptr{mbedtls_rsa_context}, @nospecialize(owner)) = new(data, owner)
end

function Base.getproperty(ctx::RSA, s::Symbol)
    if s in (:N, :E, :D, :P, :Q)
        return MPI(Ptr{mbedtls_mpi}(getfield(ctx, :data) +
            fieldoffset(mbedtls_rsa_context, Base.fieldindex(mbedtls_rsa_context, s))), ctx)
    end
    return getfield(ctx, s)
end

Base.unsafe_convert(::Type{Ptr{mbedtls_rsa_context}}, rsa::RSA) = rsa.data

function mpi_import!(mpi::Union{Ptr{mbedtls_mpi}, MPI}, b::BigInt)
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

function mpi_export!(vec::Union{Vector{UInt8}, SubArray{1, UInt8, Vector{UInt8}}}, mpi::Union{Ptr{mbedtls_mpi}, MPI})
    @err_check ccall((:mbedtls_mpi_write_binary, libmbedcrypto), Cint,
        (Ptr{mbedtls_mpi}, Ptr{UInt8}, Csize_t),
        mpi, data, sizeof(vec))
    return nothing
end

function mpi_export!(to::IOBuffer, mpi::Union{Ptr{mbedtls_mpi}, MPI})
    sz = mpi_size(mpi)
    Base.ensureroom(to, sz)
    ptr = (to.append ? to.size+1 : to.ptr)
    @GC.preserve to begin
        @err_check ccall((:mbedtls_mpi_write_binary, libmbedcrypto), Cint,
            (Ptr{mbedtls_mpi}, Ptr{UInt8}, Csize_t),
            mpi, pointer(to.data, ptr), sz)
        ptr += sz
    end
    to.size = max(to.size, ptr - 1)
    if !to.append
        to.ptr += sz
    end
    return sz
end

function mpi_size(mpi::Union{Ptr{mbedtls_mpi}, MPI})
    ccall((:mbedtls_mpi_size, libmbedcrypto), Csize_t, (Ptr{mbedtls_mpi},), mpi)
end

function pubkey_from_vals!(ctx::RSA, e::BigInt, n::BigInt)
    mpi_import!(ctx.N, n)
    mpi_import!(ctx.E, e)
    @GC.preserve ctx begin
        nptr_size = mpi_size(ctx.N)
        unsafe_store!(Ptr{Csize_t}(ctx.data+fieldoffset(mbedtls_rsa_context, 2 #= :len =#)), nptr_size)
    end
    @err_check ccall((:mbedtls_rsa_check_pubkey, libmbedcrypto), Cint,
        (Ptr{mbedtls_rsa_context},), ctx)
    ctx
end

function complete!(ctx::RSA)
    @err_check ccall((:mbedtls_rsa_complete, libmbedcrypto), Cint,
        (Ptr{mbedtls_rsa_context},), ctx)
    return nothing
end

function verify(ctx::RSA, hash_alg::MDKind, hash, signature, rng = nothing; using_public=true)
    (!using_public && rng == nothing) &&
        error("Private key verification requires the rng")
    # All errors, including validation errors throw
    @err_check ccall((:mbedtls_rsa_pkcs1_verify, libmbedcrypto), Cint,
        (Ptr{mbedtls_rsa_context}, Ptr{Cvoid}, Any, Cint, Cint, Csize_t, Ptr{UInt8}, Ptr{UInt8}),
        ctx,
        rng == nothing ? C_NULL : c_rng[],
        rng == nothing ? Ref{Any}() : rng,
        using_public ? 0 : 1,
        hash_alg, sizeof(hash), hash, signature)
end

function gen_key!(ctx::RSA, f_rng, rng, nbits, exponent)
    @err_check ccall((:mbedtls_rsa_gen_key, libmbedcrypto), Cint,
        (Ptr{mbedtls_rsa_context}, Ptr{Cvoid}, Any, Cint, Cint),
        ctx, f_rng, rng, nbits, exponent)
    ctx
end

function gen_key(rng::AbstractRNG, nbits=2048, exponent=65537)
    ctx = RSA()
    gen_key!(ctx, c_rng[], rng, nbits, exponent)
    ctx
end

function public(ctx::RSA, input, output)
    @err_check ccall((:mbedtls_rsa_public, libmbedcrypto), Cint,
        (Ptr{mbedtls_rsa_context}, Ptr{Cvoid}, Ptr{Cvoid}), ctx, input, output)
    output
end

function private(ctx::RSA, f_rng, rng, input, output)
    @err_check ccall((:mbedtls_rsa_private, libmbedcrypto), Cint,
        (Ptr{mbedtls_rsa_context}, Ptr{Cvoid}, Any, Ptr{Cvoid}, Ptr{Cvoid}),
        ctx, f_rng, rng, input, output)
    output
end

function private(ctx::RSA, rng::AbstractRNG, input, output)
    private(ctx, c_rng[], rng, input, output)
end
