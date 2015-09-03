__precompile__(false)
module Mbed

using BinDeps

@BinDeps.load_dependencies

import Base: show

const MBED_TLS = "/usr/local/lib/libmbedtls.dylib"
const MBED_CRYPTO = "/usr/local/lib/libmbedcrypto.dylib"
const MBED_X509 = "/usr/local/lib/libmbedx509.dylib"

include("constants.jl")
include("error.jl")
include("entropy.jl")
include("ctr_drbg.jl")
include("x509_crt.jl")
include("ssl.jl")

function __init__()
    __sslinit__()
end

end # module
