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

function strerror(ret, bufsize=1000)
    buf = Vector{UInt8}(uninitialized, bufsize)
    ccall((:mbedtls_strerror, libmbedcrypto), Cint,
        (Cint, Ptr{Cvoid}, Csize_t),
        ret, buf, bufsize)
    unsafe_string(pointer(buf))
end
