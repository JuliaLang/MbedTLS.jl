using BinDeps

@BinDeps.setup

mbed = library_dependency("libmbedtls", aliases=["libmbedtls", "libmbedtls.2.0.0"])
mbed_crypto = library_dependency("libmbedcrypto", aliases=["libmbedcrypto", "libmbedcrypto.2.0.0"])
mbed_x509 = library_dependency("libmbedx509", aliases=["libmbedx509", "libmbedx509.2.0.0"])

mbed_all = [mbed, mbed_crypto, mbed_x509]

provides(Sources,
        URI("https://tls.mbed.org/download/mbedtls-2.0.0-gpl.tgz"),
        mbed_all, unpacked_dir="mbedtls-2.0.0")


@unix_only begin
    mbed_dir = joinpath(BinDeps.depsdir(mbed), "src", "mbedtls-2.0.0")
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
    provides(
        Binaries,
        URI("https://malmaud.github.io/files/libmedtls.2.0.0.zip"),
        mbed_all)
end


@BinDeps.install Dict("libmbedtls"=>"MBED_TLS",
                      "libmbedcrypto"=>"MBED_CRYPTO",
                      "libmbedx509"=>"MBED_X509")
