module MbedTLS

using Random, Sockets
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

# Load mbedtls libraries from our deps.jl
const depsjl_path = joinpath(dirname(@__FILE__), "..", "deps", "deps.jl")
if !isfile(depsjl_path)
    error("MbedTLS not installed properly, run Pkg.build(\"MbedTLS\"), restart Julia and try again")
end
include(depsjl_path)

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

tls_dbg(level, filename, number, msg) = @warn "MbedTLS emitted debug info: $msg in $filename:$number"

# already defined SSLConfig and SSLContext types in ssl.jl
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

function SSLConfig(verify::Bool)
    conf = MbedTLS.SSLConfig()
    MbedTLS.config_defaults!(conf)

    entropy = MbedTLS.Entropy()
    rng = MbedTLS.CtrDrbg()
    MbedTLS.seed!(rng, entropy)
    MbedTLS.rng!(conf, rng)

    MbedTLS.authmode!(conf,
      verify ? MbedTLS.MBEDTLS_SSL_VERIFY_REQUIRED : MbedTLS.MBEDTLS_SSL_VERIFY_NONE)
    MbedTLS.dbg!(conf, tls_dbg)
    MbedTLS.ca_chain!(conf)
    conf
end

# already defined setup! in ssl.jl
associate!(tls::SSLContext, tcp::TCPSocket) = set_bio!(tls, tcp)
handshake!(tls::SSLContext) = handshake(tls)

end # module
