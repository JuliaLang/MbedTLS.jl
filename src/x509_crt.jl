type CRT
    data::Ptr{Void}
    
    function CRT()
        c = new()
        c.data = Libc.malloc(1000)
        ccall((:mbedtls_x509_crt_init, MBED_X509), Void, (Ptr{Void},), c.data)
        finalizer(c, c->begin
            ccall((:mbedtls_x509_crt_free, MBED_X509), Void, (Ptr{Void},), c.data)
            Libc.free(c.data)
        end)
        c
    end
end

show(io::IO, crt::CRT) = print(io, crt_info(crt))

function crt_info(crt::CRT)
    buf = zeros(UInt8, 1000)
    ccall((:mbedtls_x509_crt_info, MBED_X509), Cint,
        (Ptr{Void}, Csize_t, Cstring, Ptr{Void}),
        buf, 1000, "", crt.data)
    bytestring(pointer(buf))
end

function crt_parse_file!(chain, path)
    ret = ccall((:mbedtls_x509_crt_parse_file, MBED_X509), Cint,
        (Ptr{Void}, Cstring),
        chain.data, path)
    ret == 0 || mbed_err(ret)
    chain
end

crt_parse_file(path) = crt_parse_file!(CRT(), path)
