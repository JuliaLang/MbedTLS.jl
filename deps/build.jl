using BinDeps

@BinDeps.setup

function validate_mbed(name, handle)
    get_version = Libdl.dlsym(handle, :mbedtls_version_get_string)
    version_ptr = Vector{UInt8}(9)
    ccall(get_version, Void, (Ptr{Void},), version_ptr)
    version = VersionNumber(bytestring(pointer(version_ptr)))
    version >= v"2.1.1"
end

mbed = library_dependency("libmbedtls", aliases=["libmbedtls", "libmbedtls.2.1.1"], validate=validate_mbed)
mbed_crypto = library_dependency("libmbedcrypto", aliases=["libmbedcrypto", "libmbedcrypto.2.1.1"])
mbed_x509 = library_dependency("libmbedx509", aliases=["libmbedx509", "libmbedx509.2.1.1"])

mbed_all = [mbed, mbed_crypto, mbed_x509]

if haskey(ENV, "USE_GPL_MBEDTLS")  # The source code is identical except for the license text
    source_uri = URI("https://tls.mbed.org/download/mbedtls-2.1.1-gpl.tgz")
else
    source_uri = URI("https://tls.mbed.org/download/mbedtls-2.1.1-apache.tgz")
end

provides(Sources,
        source_uri,
        mbed_all, unpacked_dir="mbedtls-2.1.1")

@unix_only begin
    mbed_dir = joinpath(BinDeps.depsdir(mbed), "src", "mbedtls-2.1.1")
    provides(BuildProcess,
        (@build_steps begin
            GetSources(mbed)
            @build_steps begin
                ChangeDirectory(mbed_dir)
                 @build_steps begin
                    `cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On .`
                    `make`
                end
            end
        end), mbed_all, installed_libpath=joinpath(mbed_dir, "library"))
end

@osx_only begin
    if Pkg.installed("Homebrew") === nothing
		error("Homebrew package not installed, please run Pkg.add(\"Homebrew\")")
	end
	using Homebrew
	provides(Homebrew.HB, "mbedtls", mbed_all)
end

@windows_only begin
    unpacked_dir = Int==Int32 ? "usr/bin32" : "usr/bin64"
    provides(
        Binaries,
        URI("https://cache.e.ip.saba.us/https://malmaud.github.io/files/mbedtls-2.1.1-r1.zip"),
        mbed_all,
        unpacked_dir=unpacked_dir,
        sha = "ae10d5fea059faa949293669557c52ec50a1b0c9798835452ea2130e990b251a")
end


@BinDeps.install Dict("libmbedtls"=>"MBED_TLS",
                      "libmbedcrypto"=>"MBED_CRYPTO",
                      "libmbedx509"=>"MBED_X509")
