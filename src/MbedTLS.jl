__precompile__(true)
module MbedTLS

import Base: show

if isfile(joinpath(dirname(@__FILE__),"..","deps","deps.jl"))
    include(joinpath(dirname(@__FILE__),"..","deps","deps.jl"))
else
    error("MbedTLS not properly installed. Please run Pkg.build(\"MbedTLS\")")
end

const MBED_SUCCESS = Cint(0)

include("constants.jl")
include("error.jl")
include("hash.jl")
include("rsa.jl")
include("entropy.jl")
include("ctr_drbg.jl")
include("x509_crt.jl")
include("ssl.jl")

function __init__()
    __ctr_drbg__init__()
    __sslinit__()
end

end # module
