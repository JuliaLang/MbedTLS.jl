mutable struct CRT
    data::Ptr{Cvoid}

    function CRT()
        c = new()
        c.data = Libc.malloc(1000)  # 552
        ccall((:mbedtls_x509_crt_init, libmbedx509), Cvoid, (Ptr{Cvoid},), c.data)
        finalizer(c->begin
            ccall((:mbedtls_x509_crt_free, libmbedx509), Cvoid, (Ptr{Cvoid},), c.data)
            Libc.free(c.data)
        end, c)
        c
    end
end

show(io::IO, crt::CRT) = print(io, crt_info(crt))

function crt_info(crt::CRT)
    buf = Base.StringVector(1000)
    ret = ccall((:mbedtls_x509_crt_info, libmbedx509), Cint,
        (Ptr{Cvoid}, Csize_t, Cstring, Ptr{Cvoid}),
        buf, length(buf), "", crt.data)
    ret >= 0 || mbed_err(ret)
    resize!(buf, ret)
    return String(buf)
end

function crt_parse!(chain, buf::String)
    ret = ccall((:mbedtls_x509_crt_parse, libmbedx509), Cint,
        (Ptr{Cvoid}, Ptr{UInt8}, Csize_t),
        chain.data, buf, sizeof(buf)+1)
    ret == 0 || mbed_err(ret)
    chain
end

crt_parse!(chain, buf::IOStream) = crt_parse!(chain, String(read(buf)))

crt_parse_file(path) = crt_parse(String(read(path)))

function crt_parse(buf)
    crt = CRT()
    crt_parse!(crt, String(buf))
    crt
end
