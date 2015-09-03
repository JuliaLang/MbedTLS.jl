macro err_check(expr)
    quote
        ret = $expr
        ret == 0 || mbed_err(ret)
    end
end

immutable MbedException <: Exception
    ret::Cint
end

show(io::IO, err::MbedException) = println(io, strerror(err.ret))

mbed_err(ret) = throw(MbedException(ret))

function strerror(ret, bufsize=1000)
    buf = Vector{UInt8}(bufsize)
    ccall((:mbedtls_strerror, MBED_CRYPTO), Cint,
        (Cint, Ptr{Void}, Csize_t),
        ret, buf, bufsize)
    bytestring(pointer(buf))
end
