__precompile__(true)
module MbedTLS

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

# Types
    CtrDrbg,
    RSA,
    SSLConfig,
    Entropy,
    CRT

import Base: show

if isfile(joinpath(dirname(@__FILE__),"..","deps","deps.jl"))
    include(joinpath(dirname(@__FILE__),"..","deps","deps.jl"))
else
    error("MbedTLS not properly installed. Please run Pkg.build(\"MbedTLS\")")
end

const MBED_SUCCESS = Cint(0)

include("constants.jl")
include("error.jl")
include("md.jl")
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

end # module
