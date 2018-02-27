using BinaryProvider, Compat
# Parse some basic command-line arguments
const prefix = Prefix(joinpath(Base.LIBDIR, "../"))

const mbedtls = LibraryProduct(prefix, "libmbedtls", :MBED_TLS)
const crypto = LibraryProduct(prefix, "libmbedcrypto", :MBED_CRYPTO)
const x509 = LibraryProduct(prefix, "libmbedx509", :MBED_X509)

if !any(satisfied(lib; verbose=true) for lib in (mbedtls, crypto, x509))
    error("MbedTLS shared libraries ship with julia itself, but can't be detected. If you've removed the 'libmbedtls', 'libmbedcrypto', and/or 'libmbedx509' libraries manually, or built julia with `USE_SYSTEM_MBEDTLS`, you'll need to provide links to these libraries in `joinpath(Sys.BINDIR, \"../lib\")` or modify `MbedTLS/deps/build.jl` `Prefix` to provide the path to your system libraries.")
end
# Write out a deps.jl file that will contain mappings for our products
write_deps_file(joinpath(@__DIR__, "deps.jl"), [mbedtls, crypto, x509])
