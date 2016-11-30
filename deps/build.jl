using BinDeps
using Compat
import Compat: String

@BinDeps.setup

function validate_mbed(name, handle)
    try
        get_version = Libdl.dlsym(handle, :mbedtls_version_get_string)
        version_ptr = Vector{UInt8}(9)
        ccall(get_version, Void, (Ptr{Void},), version_ptr)
        version = VersionNumber(unsafe_string(pointer(version_ptr)))
        version >= v"2.1.1"
    catch err
        warn("Could not check MbedTLS version: $err")
        false
    end
end

mbed = library_dependency("libmbedtls", aliases=["libmbedtls", "libmbedtls.2.1.1"])
mbed_crypto = library_dependency("libmbedcrypto", aliases=["libmbedcrypto", "libmbedcrypto.2.1.1"], validate=validate_mbed)
mbed_x509 = library_dependency("libmbedx509", aliases=["libmbedx509", "libmbedx509.2.1.1"])

mbed_all = [mbed, mbed_crypto, mbed_x509]

if haskey(ENV, "USE_GPL_MBEDTLS")  # The source code is identical except for the license text
    source_uri = URI("https://cache.julialang.org/https://tls.mbed.org/download/mbedtls-2.1.1-gpl.tgz")
    srcsha = "22c76e9d8036a76e01906423b3e8a02ab0ef84027f791bd719fff8edee9c61a9"
else
    source_uri = URI("https://cache.julialang.org/https://tls.mbed.org/download/mbedtls-2.1.1-apache.tgz")
    srcsha = "8f25b6f156ae5081e91bcc58b02455926d9324035fe5f7028a6bb5bc0139a757"
end

function BinDeps.generate_steps(dep::BinDeps.LibraryDependency,h::BinDeps.CustomPathBinaries,opts)
    steps = @build_steps begin
        BinDeps.ChecksumValidator(get(opts,:SHA,get(opts,:sha,"")),h.path)
    end
end

# Use the version of MbedTLS that ships with Julia .5 and later

if is_unix()
    provides(Binaries,
        joinpath(JULIA_HOME, "..", "lib", "julia"),
        mbed_all)
end

if is_windows()
    provides(Binaries,
        JULIA_HOME,
        mbed_all)
end

# For Julia versions less than .5

provides(Sources,
        source_uri,
        mbed_all, unpacked_dir="mbedtls-2.1.1",
        SHA = srcsha)

if is_unix()
    mbed_dir = joinpath(BinDeps.depsdir(mbed), "src", "mbedtls-2.1.1")
    provides(BuildProcess,
        (@build_steps begin
            `./cmake_check.sh`
            GetSources(mbed)
            @build_steps begin
                ChangeDirectory(mbed_dir)
                 @build_steps begin
                    `cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On .`
                    `make lib`
                end
            end
        end), mbed_all, installed_libpath=joinpath(mbed_dir, "library"))
end

if is_apple()
    if Pkg.installed("Homebrew") === nothing
		error("Homebrew package not installed, please run Pkg.add(\"Homebrew\")")
	end
	using Homebrew
	provides(Homebrew.HB, "mbedtls", mbed_all)
end

if is_windows()
    unpacked_dir = Int==Int32 ? "usr/bin32" : "usr/bin64"
    provides(
        Binaries,
        URI("https://malmaud.github.io/files/mbedtls-2.1.1-r1.zip"),
        mbed_all,
        unpacked_dir=unpacked_dir,
        SHA = "ab5a86d6c35d478082722e08747742fe04bf761a8e3ac4f3c960159244bbd8d8")
end


@BinDeps.install Dict("libmbedtls"=>"MBED_TLS",
                      "libmbedcrypto"=>"MBED_CRYPTO",
                      "libmbedx509"=>"MBED_X509")
