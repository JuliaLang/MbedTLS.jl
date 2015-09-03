using BinDeps

@BinDeps.setup

mbed = library_dependency("libmbedtls", aliases=["libmbedtls", "libmbedtls.2.0.0"])

provides(Sources,
        URI("https://tls.mbed.org/download/mbedtls-2.0.0-gpl.tgz"),
        mbed, unpacked_dir="mbedtls-2.0.0")

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
    end), mbed, installed_libpath=joinpath(mbed_dir, "library"))


@BinDeps.install Dict("libmbedtls"=>"MBED_TLS")
