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
    buf = zeros(UInt8, 1000)
    ccall((:mbedtls_x509_crt_info, libmbedx509), Cint,
          (Ptr{Cvoid}, Csize_t, Cstring, Ptr{Cvoid}),
          buf, 1000, "", crt.data)
    unsafe_string(pointer(buf))
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

mutable struct CRL
    data::Ptr{Cvoid}
    function CRL()
        c = new()
        c.data = Libc.malloc(1000)  # 416
        ccall((:mbedtls_x509_crl_init, libmbedx509), Cvoid, (Ptr{Cvoid},), c.data)
        finalizer(c->begin
            ccall((:mbedtls_x509_crl_free, libmbedx509), Cvoid, (Ptr{Cvoid},), c.data)
            Libc.free(c.data)
        end, c)
        return c
    end
end

show(io::IO, crl::CRL) = print(io, crl_info(crl))

function crl_info(crl::CRL)
    buf = zeros(UInt8, 1000)
    ccall((:mbedtls_x509_crl_info, libmbedx509), Cint,
          (Ptr{Cvoid}, Csize_t, Cstring, Ptr{Cvoid}),
          buf, 1000, "", crl.data)
    unsafe_string(pointer(buf))
end

function crl_parse!(crl, buf::Vector{UInt8})
    ret = ccall((:mbedtls_x509_crl_parse, libmbedx509),
                Cint, (Ptr{Cvoid}, Ptr{UInt8}, Csize_t),
                crl.data, buf, sizeof(buf))
    ret == 0 || mbed_err(ret)
    return crl
end

crl_parse!(crl, io::IOStream) = crl_parse!(crl, read(buf))

function crl_parse_file(path::String)
    crl = CRL()
    ret = ccall((:mbedtls_x509_crl_parse_file, libmbedx509),
                Cint, (Ptr{Cvoid}, Ptr{Cstring}),
                crl.data, transcode(UInt8, path))
    ret == 0 || mbed_err(ret)
    return crl
end

function crl_parse(buf)
    crl = CRL()
    crl_parse!(crl, buf)
    crt
end

function crt_verify(crt::CRT, trust_ca::CRT, crl::CRL, cn::String)
    flags = Cuint[0]
    ret = ccall((:mbedtls_x509_crt_verify, libmbedx509),
                Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cstring}, Ptr{Cuint}, Ptr{Nothing}, Ptr{Cvoid}),
                crt.data, trust_ca.data, crl.data, transcode(UInt8, cn), flags, C_NULL, C_NULL)
    ret == 0 && return 0x00000000, "SUCCESS"
    buf = zeros(UInt8, 1024)
    ccall((:mbedtls_x509_crt_verify_info, libmbedx509),
          Cint, (Ptr{UInt8}, Csize_t, Ptr{UInt8}, Cuint),
          buf, length(buf), "", flags[1])
    return flags[1], unsafe_string(pointer(buf))
end

# Not used currently
struct CRTProfile
    allowed_mds::UInt32
    allowed_pks::UInt32
    allowed_curves::UInt32
    rsa_min_bitlen::UInt32
end

CRT_PROFILE_DEFAULT = unsafe_load(cglobal((:mbedtls_x509_crt_profile_default, libmbedx509), CRTProfile))
CRT_PROFILE_NEXT    = unsafe_load(cglobal((:mbedtls_x509_crt_profile_next,    libmbedx509), CRTProfile))
CRT_PROFILE_SUITEB  = unsafe_load(cglobal((:mbedtls_x509_crt_profile_suiteb,  libmbedx509), CRTProfile))
