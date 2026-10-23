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

show(io::IO, crt::CRT) = print(io, has_cert(crt) ? crt_info(crt) : "MbedTLS.CRT()")

# Whether `crt` holds a certificate. mbedtls can't describe an empty `CRT`: it fails with
# "buffer too small" about one of its own fixed-size buffers.
has_cert(crt::CRT) = unsafe_load(Ptr{X509CrtHead}(crt.data)).raw.len != 0

function crt_info(crt::CRT)
    has_cert(crt) || throw(ArgumentError("`crt` holds no certificate"))
    n = 1000
    while true
        buf = Base.StringVector(n)
        ret = ccall((:mbedtls_x509_crt_info, libmbedx509), Cint,
            (Ptr{Cvoid}, Csize_t, Cstring, Ptr{Cvoid}),
            buf, length(buf), "", crt.data)
        # Stop growing well past any real certificate's description, in case mbedtls means
        # one of its own fixed-size buffers.
        if ret == MBEDTLS_ERR_X509_BUFFER_TOO_SMALL && n < 1 << 24
            n *= 2
            continue
        end
        ret >= 0 || mbed_err(ret)
        return String(resize!(buf, ret))
    end
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
    crt_parse!(crt, as_string(buf))
    crt
end
