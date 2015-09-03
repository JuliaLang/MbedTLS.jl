using BinDeps

@BinDeps.setup

mbed = library_dependency("libmbedtls", aliases=["libmbedtls", "libmbedtls.2.0.0"])
mbed_crypto = library_dependency("libmbedcrypto", aliases=["libmbedcrypto", "libmbedcrypto.2.0.0"])
mbed_x509 = library_dependency("libmbedx509", aliases=["libmbedx509", "libmbedx509.2.0.0"])

provides(Sources,
        URI("https://tls.mbed.org/download/mbedtls-2.0.0-gpl.tgz"),
        [mbed, mbed_crypto, mbed_x509], unpacked_dir="mbedtls-2.0.0")

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
    end), [mbed, mbed_crypto, mbed_x509], installed_libpath=joinpath(mbed_dir, "library"))


@BinDeps.install Dict("libmbedtls"=>"MBED_TLS",
                      "libmbedcrypto"=>"MBED_CRYPTO",
                      "libmbedx509"=>"MBED_X509")
