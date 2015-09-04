abstract MbedHash

#  Message digest constants from mbedtls_md_type_t enum in md.h
const MBEDTLS_MD_NONE=0
const MBEDTLS_MD_MD2=1
const MBEDTLS_MD_MD4=2
const MBEDTLS_MD_MD5=3
const MBEDTLS_MD_SHA1=4

macro define_hash(typename, abbr, sz, digest_sz)
    start_sym = Symbol("mbedtls_$(abbr)_starts")
    init_sym = Symbol("mbedtls_$(abbr)_init")
    free_sym = Symbol("mbedtls_$(abbr)_free")
    update_sym = Symbol("mbedtls_$(abbr)_update")
    finish_sym = Symbol("mbedtls_$(abbr)_finish")
    esc_type = esc(typename)
    quote

        type $esc_type <: MbedHash
            data::Ptr{Void}

            function $esc_type()
                ctx = new()
                ctx.data = Libc.malloc($sz)
                ccall(($(QuoteNode(init_sym)), MBED_CRYPTO), Void, (Ptr{Void},), ctx.data)
                starts(ctx)

                finalizer(ctx, ctx->begin
                    ccall(($(QuoteNode(free_sym)), MBED_CRYPTO), Void, (Ptr{Void},), ctx.data)
                    Libc.free(ctx.data)
                end)

                ctx
            end
        end

        function $(esc(:starts))(ctx::$esc_type)
            ccall(($(QuoteNode(start_sym)), MBED_CRYPTO), Void, (Ptr{Void},), ctx.data)
        end

        function $(esc(:update))(ctx::$esc_type, input::Ptr{UInt8}, len)
            ccall(($(QuoteNode(update_sym)), MBED_CRYPTO), Void,
                (Ptr{Void}, Ptr{Void}, Csize_t),
                ctx.data, input, len)
        end


        function $(esc(:finish))(ctx::$esc_type, output::Ptr{UInt8})
            ccall(($(QuoteNode(finish_sym)), MBED_CRYPTO), Void,
                (Ptr{Void}, Ptr{UInt8}),
                ctx.data, output)
        end

        $(esc(:digest_size))(ctx::Type{$esc_type}) = $digest_sz

    end
end

@define_hash MD5 md5 150 16
@define_hash SHA1 sha1 100 20
@define_hash SHA256 sha256 150 32
@define_hash SHA512 sha512 300 64

function Base.write(ctx::MbedHash, buf::Vector{UInt8})
    update(ctx, pointer(buf), sizeof(buf))
end

function digest!(ctx, buf)
    @assert length(buf) ≥ digest_size(typeof(ctx))
    finish(ctx, pointer(buf))
    buf
end

function digest(ctx)
    output = Vector{UInt8}(digest_size(typeof(ctx)))
    digest!(ctx, output)
    output
end

function Base.hash{T<:MbedHash}(kind::Type{T}, buf::Vector{UInt8})
    ctx = T()
    write(ctx, buf)
    digest(ctx)
end

Base.hash{T<:MbedHash}(kind::Type{T}, buf::AbstractString) =
  hash(kind, bytestring(buf).data)

Base.hash{T<:MbedHash}(kind::Type{T}, buf::AbstractVector) =
  hash(kind, collect(buf))
