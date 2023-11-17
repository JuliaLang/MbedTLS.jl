macro err_check(expr)
    quote
        ret = $(esc(expr))
        ret == 0 || mbed_err(ret)
        ret
    end
end

struct MbedException <: Exception
    ret::Cint
end

function show(io::IO, err::MbedException)
    print(io, "MbedTLS error code $(err.ret): $(strerror(err.ret))")
end

mbed_err(ret) = throw(MbedException(ret))
mbed_ioerr(ret) = throw(Base.IOError(strerror(ret), ret))

function strerror(ret, bufsize=1000)
    buf = Base.StringVector(bufsize)
    ccall((:mbedtls_strerror, libmbedcrypto), Cvoid,
        (Cint, Ptr{Cvoid}, Csize_t),
        ret, buf, bufsize)
    resize!(buf, something(findfirst(iszero, buf), length(buf) + 1) - 1)
    s = String(buf)
    if ret == MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE
        s *= " (You may need to enable `ssl_conf_renegotiation!`. See " *
        "https://github.com/JuliaWeb/HTTP.jl/issues/342#issuecomment-432921180)"
    end
    return s
end
