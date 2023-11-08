@enum(CipherID,
    CIPHER_ID_NONE=0,
    CIPHER_ID_NULL,
    CIPHER_AES,
    CIPHER_DES,
    CIPHER_3DES,
    CIPHER_CAMELLIA,
    CIPHER_BLOWFISH,
    CIPHER_ARC4)

@enum(CipherKind,
    CIPHER_NONE = 0,
    CIPHER_NULL,
    CIPHER_AES_128_ECB,
    CIPHER_AES_192_ECB,
    CIPHER_AES_256_ECB,
    CIPHER_AES_128_CBC,
    CIPHER_AES_192_CBC,
    CIPHER_AES_256_CBC,
    CIPHER_AES_128_CFB128,
    CIPHER_AES_192_CFB128,
    CIPHER_AES_256_CFB128,
    CIPHER_AES_128_CTR,
    CIPHER_AES_192_CTR,
    CIPHER_AES_256_CTR,
    CIPHER_AES_128_GCM,
    CIPHER_AES_192_GCM,
    CIPHER_AES_256_GCM,
    CIPHER_CAMELLIA_128_ECB,
    CIPHER_CAMELLIA_192_ECB,
    CIPHER_CAMELLIA_256_ECB,
    CIPHER_CAMELLIA_128_CBC,
    CIPHER_CAMELLIA_192_CBC,
    CIPHER_CAMELLIA_256_CBC,
    CIPHER_CAMELLIA_128_CFB128,
    CIPHER_CAMELLIA_192_CFB128,
    CIPHER_CAMELLIA_256_CFB128,
    CIPHER_CAMELLIA_128_CTR,
    CIPHER_CAMELLIA_192_CTR,
    CIPHER_CAMELLIA_256_CTR,
    CIPHER_CAMELLIA_128_GCM,
    CIPHER_CAMELLIA_192_GCM,
    CIPHER_CAMELLIA_256_GCM,
    CIPHER_DES_ECB,
    CIPHER_DES_CBC,
    CIPHER_DES_EDE_ECB,
    CIPHER_DES_EDE_CBC,
    CIPHER_DES_EDE3_ECB,
    CIPHER_DES_EDE3_CBC,
    CIPHER_BLOWFISH_ECB,
    CIPHER_BLOWFISH_CBC,
    CIPHER_BLOWFISH_CFB64,
    CIPHER_BLOWFISH_CTR,
    CIPHER_ARC4_128,
    CIPHER_AES_128_CCM,
    CIPHER_AES_192_CCM,
    CIPHER_AES_256_CCM,
    CIPHER_CAMELLIA_128_CCM,
    CIPHER_CAMELLIA_192_CCM,
    CIPHER_CAMELLIA_256_CCM)

@enum(CipherMode,
    CIPHER_MODE_NONE = 0,
    CIPHER_MODE_ECB,
    CIPHER_MODE_CBC,
    CIPHER_MODE_CFB,
    CIPHER_MODE_OFB,
    CIPHER_MODE_CTR,
    CIPHER_MODE_GCM,
    CIPHER_MODE_STREAM,
    CIPHER_MODE_CCM)

@enum(Padding,
    PADDING_PKCS7 = 0,
    PADDING_ONE_AND_ZEROS,
    PADDING_ZEROS_AND_LEN,
    PADDING_ZEROS,
    PADDING_NONE)


@enum(Operation,
    OPERATION_NONE = -1,
    DECRYPT = 0,
    ENCRYPT)

mutable struct CipherInfo
    data::Ptr{Cvoid}
end

mutable struct Cipher
    data::Ptr{Cvoid}

    function Cipher()
        ctx = new()
        ctx.data = Libc.malloc(200) # 88
        ccall((:mbedtls_cipher_init, libmbedcrypto), Cvoid,
            (Ptr{Cvoid},), ctx.data)

        finalizer(ctx->begin
            ccall((:mbedtls_cipher_free, libmbedcrypto), Cvoid,
                (Ptr{Cvoid},), ctx.data)
            Libc.free(ctx.data)
        end, ctx)

        ctx
    end
end

function CipherInfo(name::AbstractString)
    ptr = ccall((:mbedtls_cipher_info_from_string, libmbedcrypto), Ptr{Cvoid},
        (Cstring,), String(name))
    ptr == C_NULL && error("No cipher for $name found")
    CipherInfo(ptr)
end

function CipherInfo(kind::CipherKind)
    ptr = ccall((:mbedtls_cipher_info_from_type, libmbedcrypto), Ptr{Cvoid},
        (Cint,), Int(kind))
    ptr == C_NULL && error("No cipher for $kind found")
    CipherInfo(ptr)
end

"""
`CipherInfo(id::CipherID, key_bitlength, mode::CipherMode) -> CipherInfo`

Construct a custom cipher info object.

- `id`: A CipherID, such as CIPHER_AES of CIPHER_BLOWFIHS
- `key_bitlength`: The bit length of the secret key. Available options depend
on the specific cipher id.
- `mode`: Either `Encrypt` or `Decrypt` to indicate which cipher operation will
be performed with this cipher info.
"""
function CipherInfo(id::CipherID, key_bitlen, mode::CipherMode)
    ptr = ccall((:mbedtls_cipher_info_from_values, libmbedcrypto), Ptr{Cvoid},
        (Cint, Cint, Cint), Int(id), key_bitlen, Int(mode))
    ptr == C_NULL && error("No cipher for ($id, $(key_bitlen), $mode) found")
    CipherInfo(ptr)
end

"""
`CipherInfo(id::CipherID) -> CipherInfo`

Build a CipherInfo for the given cipher id using the strongest available
key size and the CBC block mode.

*Warning*: In CBC block mode, it is imperative that you use a unique IV (initial value)
for each encryption operation to maintain security.
"""
function CipherInfo(id::CipherID)
    canonical_map = Dict(
        CIPHER_AES => CIPHER_AES_256_CBC,
        CIPHER_DES => CIPHER_DES_CBC,
        CIPHER_CAMELLIA => CIPHER_CAMELLIA_256_CBC,
        CIPHER_BLOWFISH => CIPHER_BLOWFISH_CBC,
        CIPHER_ARC4 => CIPHER_ARC4_128
    )
    if haskey(canonical_map, id)
        canonical_map[id]
    else
        error("No default cipher found for $id. Use the three-argument constructor
              of CipherInfo to explicitly create a cipher info object.")
    end
end

function Cipher(info::CipherInfo)
    cipher = Cipher()
    @err_check ccall((:mbedtls_cipher_setup, libmbedcrypto), Cint,
        (Ptr{Cvoid}, Ptr{Cvoid}), cipher.data, info.data)
    cipher
end

"""
`Cipher(info::Union{CipherID, CipherKind}) -> Cipher`

Construct a cipher object and set it to use the specified cipher algorithm.

The algorithm can either be specific (ie, `CIPHER_AES_256_CBC`), or general
(ie, `CIPHER_AES`). In the latter case, a default choice of specific cipher will
be used. See `?CipherInfo` for more details.
"""
Cipher(info::Union{CipherID, CipherKind}) = Cipher(CipherInfo(info))

function Base.show(io::IO, cipher::Cipher)
    print(io, "Cipher($(cipher.data)")
end

function get_key_bitlen(cipher::Cipher)
    ret = ccall((:mbedtls_cipher_get_key_bitlen, libmbedcrypto), Cint,
        (Ptr{Cvoid},), cipher.data)
    Int(ret)
end

tobytes(x::Vector{UInt8}) = x
tobytes(x::Base.CodeUnits) = x
tobytes(x) = codeunits(x)

function set_key!(cipher::Cipher, key, op::Operation)
    key_b = tobytes(key)
    keysize = 8 * sizeof(key_b)  # Convert key size from bytes to bits
    @err_check ccall((:mbedtls_cipher_setkey, libmbedcrypto), Cint,
        (Ptr{Cvoid}, Ptr{UInt8}, Cint, Cint),
        cipher.data, key_b, keysize, Int(op))
    key
end

function set_padding_mode!(cipher::Cipher, padding::Padding)
    @err_check ccall((:mbedtls_cipher_set_padding_mode, libmbedcrypto), Cint,
        (Ptr{Cvoid}, Cint), cipher.data, Int(padding))
end

function set_iv!(cipher::Cipher, iv)
    iv_b = tobytes(iv)
    @err_check ccall((:mbedtls_cipher_set_iv, libmbedcrypto), Cint,
        (Ptr{Cvoid}, Ptr{UInt8}, Csize_t),
        cipher.data, iv_b, sizeof(iv_b))
end

"""
`update!(cipher::Cipher, buf_in, buf_out::Vector{UInt8}) -> Int`

Run the given cipher on `buf_in` (a String or `Vector{UInt8}`) and
store the result of the cipher in `buf_out` (a `Vector{UInt8}`).

It is your responsibility to ensure that `buf_out` is at least as large as necessary
to hold the result. It should be at least as big as the size of `buf_in` plus the
block size associated with `cipher`.
"""
function update!(cipher::Cipher, buf_in, buf_out)
    buf_in_b = tobytes(buf_in)
    out_ref = Ref{Csize_t}(sizeof(buf_out))
    @err_check ccall((:mbedtls_cipher_update, libmbedcrypto), Cint,
        (Ptr{Cvoid}, Ptr{Cvoid}, Csize_t, Ptr{Cvoid}, Ptr{Csize_t}),
        cipher.data, buf_in, sizeof(buf_in), buf_out, out_ref)
    Int(out_ref[])
end

function finish!(cipher::Cipher, buf_out)
    out_ref = Ref{Csize_t}(sizeof(buf_out))
    @err_check ccall((:mbedtls_cipher_finish, libmbedcrypto), Cint,
        (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Csize_t}),
        cipher.data, buf_out, out_ref)
    Int(out_ref[])
end

function process_iv(iv, cipher)
    if isempty(iv)
        process_iv(nothing)
    else
        iv_b = tobytes(iv)
        iv_b, sizeof(iv_b)
    end
end

function process_iv(iv::Nothing, cipher)
    # todo: Don't hard-code a block size (this assumes 128-bit, as for AES)
    # todo: Think about what appropriate default (if any) should be used here
    zeros(Int8, 16), 16
end

function crypt!(cipher::Cipher, iv, buf_in, buf_out)
    olen_ref = Ref{Csize_t}(sizeof(buf_out))
    iv_b, iv_size = process_iv(iv, cipher)
    buf_in_b = tobytes(buf_in)
    @err_check ccall((:mbedtls_cipher_crypt, libmbedcrypto), Cint,
        (Ptr{Cvoid}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Ptr{Csize_t}),
        cipher.data, iv_b, iv_size, buf_in_b, sizeof(buf_in_b),
        buf_out, olen_ref)
    Int(olen_ref[])
end

crypt!(cipher::Cipher, buf_in, buf_out) = crypt!(cipher, C_NULL, buf_in, buf_out)

function crypt(cipher_info, op::Operation, key, iv, msg)
    max_block_size = 256  # todo: obtain this dynamically from mbedtls
    buf = tobytes(msg)
    cipher = Cipher(cipher_info)
    set_key!(cipher, key, op)
    buf_out = Vector{UInt8}(undef, sizeof(buf) + max_block_size)
    olen = crypt!(cipher, iv, buf, buf_out)
    resize!(buf_out, olen)
    buf_out
end

"""
`encrypt(cipher, key, msg, [iv]) -> Vector{UInt8}`

Encrypt a message using the given cipher. The cipher can be specified as

- a generic cipher (like CIPHER_AES)
- a specific cipher (like CIPHER_AES_256_CBC)
- a Cipher object

`key` is the symmetric key used for cryptography, given as either a String or a
`Vector{UInt8}`. It must be the right length for the chosen cipher; for example,
CIPHER_AES_256_CBC requires a 32-byte (256-bit) key.

`msg` is the message to be encoded. It should either be convertible to a String
or be a `Vector{UInt8}`.

`iv` is the initialization vector, whose size must match the block size of the
cipher (eg, 16 bytes for AES). By default, it will be set to all zeros, which
is not secure. For security reasons, it should be set to a different value for each
encryption operation.
"""
encrypt(cipher, key, msg, iv=nothing) = crypt(cipher, ENCRYPT, key, iv, msg)

"""
`decrypt(cipher, key, msg, [iv]) -> Vector{UInt8}`

Decrypt a message using the given cipher. The cipher can be specified as

- a generic cipher (like CIPHER_AES)
- a specific cipher (like CIPHER_AES_256_CBC)
- a Cipher object

`key` is the symmetric key used for cryptography, given as either a String or a
`Vector{UInt8}`. It must be the right length for the chosen cipher; for example,
CIPHER_AES_256_CBC requires a 32-byte (256-bit) key.

`msg` is the message to be encoded. It should either be convertible to a String
or be a `Vector{UInt8}`.

`iv` is the initialization vector, whose size must match the block size of the
cipher (eg, 16 bytes for AES) and correspond to the iv used by the encryptor.
By default, it will be set to all zeros.
"""
decrypt(cipher, key, msg, iv=nothing) = crypt(cipher, DECRYPT, key, iv, msg)
