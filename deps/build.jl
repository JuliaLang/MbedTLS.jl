using Compat

need_to_build_manually = true

function validate_mbed(name, handle)
    try
        get_version = Libdl.dlsym(handle, :mbedtls_version_get_string)
        version_ptr = fill(0x00, 9)
        ccall(get_version, Void, (Ptr{Void},), version_ptr)
        version = VersionNumber(unsafe_string(pointer(version_ptr)))
        version >= v"2.1.1"
    catch err
        warn("Could not check MbedTLS version: $err")
        false
    end
end

# if we detect correctly-versioned shared libraries on the system
# (which should be the case with normal julia 0.5 installations)
# we don't need to build anything
systemlibs =
"""
const MBED_TLS = "libmbedtls"
const MBED_CRYPTO = "libmbedcrypto"
const MBED_X509 = "libmbedx509"
"""

if Libdl.dlopen_e("libmbedtls")    != C_NULL &&
   Libdl.dlopen_e("libmbedcrypto") != C_NULL &&
   Libdl.dlopen_e("libmbedx509")   != C_NULL &&
   validate_mbed("", Libdl.dlopen_e("libmbedcrypto")) &&
   get(ENV, "FORCE_BUILD", "") != "true"
   println("Using system libraries...")
   if !isfile("deps.jl") || read("deps.jl", String) != systemlibs
       open("deps.jl", "w") do f
           write(f, systemlibs)
       end
   end
   need_to_build_manually = false
end

using BinDeps
@BinDeps.setup

if need_to_build_manually
    println("Manual build...")
    # If we somehow already have a deps from system-libraries, but are now manually building
    # make sure we delete the old deps.jl
    isfile("deps.jl") && read("deps.jl", String) == systemlibs && rm("deps.jl")

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

    provides(Sources,
            source_uri,
            mbed_all, unpacked_dir="mbedtls-2.1.1",
            SHA = srcsha)

    if Compat.Sys.isunix()
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

    if Compat.Sys.isapple()
        if Pkg.installed("Homebrew") === nothing
            error("Homebrew package not installed, please run Pkg.add(\"Homebrew\")")
        end
        using Homebrew
        provides(Homebrew.HB, "mbedtls", mbed_all)
    end

    if Compat.Sys.iswindows()
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
end
