type CRT
    data::Ptr{Void}

    function CRT()
        c = new()
        c.data = Libc.malloc(1000)  # 552
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

function crt_parse!(chain, buf::ByteString)
    ret = ccall((:mbedtls_x509_crt_parse, MBED_X509), Cint,
        (Ptr{Void}, Ptr{UInt8}, Csize_t),
        chain.data, buf, sizeof(buf)+1)
    ret == 0 || mbed_err(ret)
    chain
end

crt_parse!(chain, buf::IOStream) = crt_parse!(chain, readstring(buf))

crt_parse_file(path) = crt_parse(readstring(path))

function crt_parse(buf)
    crt = CRT()
    crt_parse!(crt, bytestring(buf))
    crt
end
