mutable struct CRL
    data::Ptr{Cvoid}

    function CRL()
        c = new()
        c.data = Libc.malloc(1000)  # 552
        ccall((:mbedtls_x509_crl_init, libmbedx509), Cvoid, (Ptr{Cvoid},), c.data)
        finalizer(c->begin
            ccall((:mbedtls_x509_crl_free, libmbedx509), Cvoid, (Ptr{Cvoid},), c.data)
            Libc.free(c.data)
        end, c)
        c
    end
end

show(io::IO, crl::CRL) = print(io, crl_info(crl))

function crl_info(crl::CRL)
    buf = zeros(UInt8, 1000)
    ccall((:mbedtls_x509_crl_info, libmbedx509), Cint,
        (Ptr{Cvoid}, Csize_t, Cstring, Ptr{Cvoid}),
        buf, 1000, "", crl.data)
    GC.@preserve buf unsafe_string(pointer(buf))
end

function crl_parse!(chain, buf::String)
    ret = ccall((:mbedtls_x509_crl_parse, libmbedx509), Cint,
        (Ptr{Cvoid}, Ptr{UInt8}, Csize_t),
        chain.data, buf, sizeof(buf)+1)
    ret == 0 || mbed_err(ret)
    chain
end

crl_parse!(chain, buf::IOStream) = crl_parse!(chain, String(read(buf)))

crl_parse_file(path) = crl_parse(String(read(path)))

function crl_parse(buf)
    crl = CRL()
    crl_parse!(crl, String(buf))
    crl
end
