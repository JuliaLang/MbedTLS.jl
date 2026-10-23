# `Base.GMP.libgmp` was added in Julia 1.9
const libgmp = isdefined(Base.GMP, :libgmp) ? Base.GMP.libgmp : :libgmp

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
    ccall((:__gmpz_export,libgmp), Ptr{Cvoid},
            (Ptr{Cvoid}, Ptr{Csize_t}, Cint, Csize_t, Cint, Csize_t, Ref{BigInt}),
            data, count, 1, 1, 1, 0, b)
    # Import into mbedtls; GMP writes no bytes for zero.
    @err_check ccall((:mbedtls_mpi_read_binary, libmbedcrypto), Cint,
        (Ptr{mbedtls_mpi}, Ptr{UInt8}, Csize_t),
        mpi, data, count[])
end

"""
    mpi_export(mpi) -> Vector{UInt8}

Return the big-endian bytes of `mpi`, without leading zeros.
"""
function mpi_export(mpi::Union{Ptr{mbedtls_mpi}, MPI})
    buf = Vector{UInt8}(undef, mpi_size(mpi))
    @err_check ccall((:mbedtls_mpi_write_binary, libmbedcrypto), Cint,
        (Ptr{mbedtls_mpi}, Ptr{UInt8}, Csize_t),
        mpi, buf, sizeof(buf))
    return buf
end

"""
    mpi_export!(io::IO, mpi) -> Int

Write the big-endian bytes of `mpi`, without leading zeros, to `io`, and return the number
of bytes written.
"""
mpi_export!(io::IO, mpi::Union{Ptr{mbedtls_mpi}, MPI}) = write(io, mpi_export(mpi))

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

rsa_len(ctx::RSA) = Int(ccall((:mbedtls_rsa_get_len, libmbedcrypto), Csize_t,
    (Ptr{mbedtls_rsa_context},), ctx))

# The raw RSA functions read and write `rsa_len(ctx)` bytes and take no buffer sizes.
function check_rsa_buffers(ctx::RSA, bufs...)
    n = rsa_len(ctx)
    for buf in bufs
        buf isa Ptr || sizeof(buf) >= n ||
            throw(ArgumentError("buffers for this RSA key need $n bytes, not $(sizeof(buf))"))
    end
    return
end

function complete!(ctx::RSA)
    @err_check ccall((:mbedtls_rsa_complete, libmbedcrypto), Cint,
        (Ptr{mbedtls_rsa_context},), ctx)
    return nothing
end

function verify(ctx::RSA, hash_alg::MDKind, hash, signature, rng = nothing; using_public=true)
    (!using_public && rng == nothing) &&
        error("Private key verification requires the rng")
    check_hash_size(hash_alg, hash)
    check_rsa_buffers(ctx, signature)
    # All errors, including validation errors throw
    @err_check ccall((:mbedtls_rsa_pkcs1_verify, libmbedcrypto), Cint,
        (Ptr{mbedtls_rsa_context}, Ptr{Cvoid}, Any, Cint, Cint, Cuint, Ptr{UInt8}, Ptr{UInt8}),
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
    check_rsa_buffers(ctx, input, output)
    @err_check ccall((:mbedtls_rsa_public, libmbedcrypto), Cint,
        (Ptr{mbedtls_rsa_context}, Ptr{Cvoid}, Ptr{Cvoid}), ctx, input, output)
    output
end

function private(ctx::RSA, f_rng, rng, input, output)
    check_rsa_buffers(ctx, input, output)
    @err_check ccall((:mbedtls_rsa_private, libmbedcrypto), Cint,
        (Ptr{mbedtls_rsa_context}, Ptr{Cvoid}, Any, Ptr{Cvoid}, Ptr{Cvoid}),
        ctx, f_rng, rng, input, output)
    output
end

function private(ctx::RSA, rng::AbstractRNG, input, output)
    private(ctx, c_rng[], rng, input, output)
end
