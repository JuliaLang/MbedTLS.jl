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

secrets_log = ""
secrets_log_file = ""
secrets_log_state = :incomplete

function tls_dbg_log_secrets(level, filename, number, msg)
    global secrets_log
    global secrets_log_file
    global secrets_log_state
    if secrets_log_state == :complete
        return
    elseif msg == "dumping 'client hello, random bytes' (32 bytes)\n"
        secrets_log = "CLIENT_RANDOM "
        secrets_log_state = :client_random
    elseif msg == "dumping 'master secret' (48 bytes)\n"
        secrets_log_state = :master_secret
        secrets_log *= " "
    elseif secrets_log_state in (:client_random, :master_secret)
        if occursin(r"^00[0-2]0:", msg)
            secrets_log *= join(split(msg)[2:17])
        else
            if secrets_log_state == :master_secret
                secrets_log *= "\n"
                open(secrets_log_file, append=true) do io
                    write(io, secrets_log)
                end
                secrets_log_state = :incomplete
                secrets_log = ""
            else
                secrets_log_state = :incomplete
            end
        end
    end
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
    if log_secrets !== nothing
        global secrets_log_file = log_secrets
        set_dbg_level(4)
        MbedTLS.dbg!(conf, tls_dbg_log_secrets)
    else
        MbedTLS.dbg!(conf, tls_dbg)
    end
    MbedTLS.ca_chain!(conf)
    conf
end

# already defined setup! in ssl.jl
associate!(tls::SSLContext, tcp::TCPSocket) = set_bio!(tls, tcp)
handshake!(tls::SSLContext) = handshake(tls)

end # module
