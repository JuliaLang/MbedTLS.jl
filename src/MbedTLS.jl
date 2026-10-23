module MbedTLS

using Random, Sockets, MbedTLS_jll, MozillaCACerts_jll, NetworkOptions
import Sockets: TCPSocket

export
# Message digests
    MD_NONE,
    MD_MD2,
    MD_MD4,
    MD_MD5,
    MD_SHA1,
    MD_SHA224,
    MD_SHA256,
    MD_SHA384,
    MD_SHA,
    digest,
    digest!,

# Symmetric encryption,
    encrypt,
    decrypt,
    Cipher,
    CIPHER_AES,
    CIPHER_DES,
    CIPHER_3DES,
    CIPHER_CAMELLIA,
    CIPHER_BLOWFISH,
    CIPHER_ARC4,

# Types
    CtrDrbg,
    RSA,
    SSLConfig,
    Entropy,
    CRT

import Base: show

const MBED_SUCCESS = Cint(0)

include("constants.jl")
include("error.jl")
include("md.jl")
include("cipher.jl")
include("rsa.jl")
include("entropy.jl")
include("ctr_drbg.jl")
include("pk.jl")
include("x509_crt.jl")
include("ssl.jl")

function __init__()
    __ctr_drbg__init__()
    __sslinit__()
    __entropyinit__()
end

tls_dbg(level, filename, number, msg) = Base.@debug "from MbedTLS" msg _file=filename _line=number

# Appends the NSS key log line for each TLS 1.2 handshake to the file `path`.
function f_export_keys(path::String, ms::Ptr{UInt8}, kb::Ptr{UInt8}, maclen::Csize_t,
                       keylen::Csize_t, ivlen::Csize_t, client_random::Ptr{UInt8},
                       server_random::Ptr{UInt8}, tls_prf_type::Cint)
    try
        line = string("CLIENT_RANDOM ", bytes2hex(unsafe_wrap(Array, client_random, 32)), " ",
                      bytes2hex(unsafe_wrap(Array, ms, 48)), "\n")
        open(io -> write(io, line), path; append=true)
    catch
        # Losing a key log line must not abort the handshake from inside mbedtls.
    end
    return Cint(0)
end

"""
    SSLConfig(cert_file, key_file)

Initialise an SSLConfig from a certificate and key file on disk.
This is probably the method you want if you are the server in an HTTPS connection or similar.

# Example
```
julia> MbedTLS.SSLConfig("self-signed-certificate.pem", "keyfile.pem")
MbedTLS.SSLConfig()
```
"""
function SSLConfig(cert_file, key_file)
    ssl_cert = MbedTLS.crt_parse_file(cert_file)
    key = MbedTLS.parse_keyfile(key_file)
    conf = MbedTLS.SSLConfig()
    entropy = MbedTLS.Entropy()
    rng = MbedTLS.CtrDrbg()
    MbedTLS.config_defaults!(conf, endpoint=MbedTLS.MBEDTLS_SSL_IS_SERVER)
    MbedTLS.seed!(rng, entropy)
    MbedTLS.rng!(conf, rng)
    MbedTLS.own_cert!(conf, ssl_cert, key)
    MbedTLS.dbg!(conf, tls_dbg)
    return conf
end

"""
    SSLConfig(verify::Bool; log_secrets=nothing)

Initialise a client SSLConfig for connecting to a server.

If `verify` is false, do not check that certificates are valid.

If `log_secrets` is a string, save connection secrets to a file with that name.
This is useful for decrypting traffic captured with Wireshark when debugging.
"""
function SSLConfig(verify::Bool; log_secrets=nothing)
    conf = MbedTLS.SSLConfig()
    MbedTLS.config_defaults!(conf)

    entropy = MbedTLS.Entropy()
    rng = MbedTLS.CtrDrbg()
    MbedTLS.seed!(rng, entropy)
    MbedTLS.rng!(conf, rng)

    MbedTLS.authmode!(conf,
      verify ? MbedTLS.MBEDTLS_SSL_VERIFY_REQUIRED : MbedTLS.MBEDTLS_SSL_VERIFY_NONE)
    MbedTLS.dbg!(conf, tls_dbg)
    if log_secrets !== nothing
        conf.keylog = String(log_secrets)
        ccall((:mbedtls_ssl_conf_export_keys_ext_cb, libmbedtls), Cvoid,
            (Ptr{Cvoid}, Ptr{Cvoid}, Any), conf.data,
            @cfunction(f_export_keys, Cint, (Ref{String}, Ptr{UInt8}, Ptr{UInt8}, Csize_t,
                       Csize_t, Csize_t, Ptr{UInt8}, Ptr{UInt8}, Cint)),
            conf.keylog)
    end
    MbedTLS.ca_chain!(conf)
    conf
end

# already defined setup! in ssl.jl
associate!(tls::SSLContext, tcp::TCPSocket) = set_bio!(tls, tcp)
handshake!(tls::SSLContext) = handshake(tls)

end # module
