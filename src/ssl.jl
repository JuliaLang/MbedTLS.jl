type SSLConfig
    data::Ptr{Void}
    rng
    chain::CRT
    dbg
    cert
    key
    alpn_protos

    function SSLConfig()
        conf = new()
        conf.data = Libc.malloc(1000)  # 360
        ccall((:mbedtls_ssl_config_init, MBED_TLS), Void, (Ptr{Void},), conf.data)
        finalizer(conf, conf->begin
            ccall((:mbedtls_ssl_config_free, MBED_TLS), Void, (Ptr{Void},), conf.data)
            Libc.free(conf.data)
        end
        )
        conf
    end
end

type SSLContext <: IO
    data::Ptr{Void}
    config::SSLConfig
    isopen::Bool
    bio

    function SSLContext()
        ctx = new()
        ctx.data = Libc.malloc(1000)  # 488
        ccall((:mbedtls_ssl_init, MBED_TLS), Void, (Ptr{Void},), ctx.data)
        finalizer(ctx, ctx->begin
            ccall((:mbedtls_ssl_free, MBED_TLS), Void, (Ptr{Void},), ctx.data)
            Libc.free(ctx.data)
        end
        )
        ctx
    end
end

function config_defaults!(config::SSLConfig; endpoint=MBEDTLS_SSL_IS_CLIENT,
    transport=MBEDTLS_SSL_TRANSPORT_STREAM, preset=MBEDTLS_SSL_PRESET_DEFAULT)
    @err_check ccall((:mbedtls_ssl_config_defaults, MBED_TLS), Cint,
        (Ptr{Void}, Cint, Cint, Cint),
        config.data, endpoint, transport, preset)
end

function authmode!(config::SSLConfig, auth)
    ccall((:mbedtls_ssl_conf_authmode, MBED_TLS), Void,
        (Ptr{Void}, Cint),
        config.data, auth)
end

function rng!(config::SSLConfig, f_rng::Ptr{Void}, ctx)
    ccall((:mbedtls_ssl_conf_rng, MBED_TLS), Void,
        (Ptr{Void}, Ptr{Void}, Ptr{Void}),
        config.data, f_rng, ctx)
end

function rng!(config::SSLConfig, rng::AbstractRNG)
    config.rng = rng
    rng!(config, c_rng, pointer_from_objref(rng))
end

function ca_chain!(config::SSLConfig, chain=crt_parse_file(TRUSTED_CERT_FILE))
    config.chain = chain
    ccall((:mbedtls_ssl_conf_ca_chain, MBED_TLS), Void,
        (Ptr{Void}, Ptr{Void}, Ptr{Void}),
        config.data, chain.data, C_NULL)
end

function own_cert!(config::SSLConfig, cert::CRT, key::PKContext)
    config.cert = cert
    config.key = key
    @err_check ccall((:mbedtls_ssl_conf_own_cert, MBED_TLS), Cint,
        (Ptr{Void}, Ptr{Void}, Ptr{Void}),
        config.data, cert.data, key.data)
end

function setup!(ctx::SSLContext, conf::SSLConfig)
    ctx.config = conf
    @err_check ccall((:mbedtls_ssl_setup, MBED_TLS), Cint,
        (Ptr{Void}, Ptr{Void}),
        ctx.data, conf.data)
end

function set_bio!(ssl_ctx::SSLContext, ctx, f_send::Ptr{Void}, f_recv::Ptr{Void})
    ccall((:mbedtls_ssl_set_bio, MBED_TLS), Void,
        (Ptr{Void}, Ptr{Void}, Ptr{Void}, Ptr{Void}, Ptr{Void}),
        ssl_ctx.data, ctx, f_send, f_recv, C_NULL)
end

function f_send(c_ctx, c_msg, sz)
    jl_ctx = unsafe_pointer_to_objref(c_ctx)
    jl_msg = unsafe_wrap(Array, c_msg, sz, false)
    return Cint(write(jl_ctx, jl_msg))
end

function f_recv(c_ctx, c_msg, sz)
    jl_ctx = unsafe_pointer_to_objref(c_ctx)
    jl_msg = unsafe_wrap(Array, c_msg, sz, false)
    n = readbytes!(jl_ctx, jl_msg, sz)
    return Cint(n)
end

function set_bio!{T<:IO}(ssl_ctx::SSLContext, jl_ctx::T)
    ssl_ctx.bio = jl_ctx
    set_bio!(ssl_ctx, pointer_from_objref(jl_ctx), c_send, c_recv)
    nothing
end

function dbg!(conf::SSLConfig, f::Ptr{Void}, p)
    ccall((:mbedtls_ssl_conf_dbg, MBED_TLS), Void,
        (Ptr{Void}, Ptr{Void}, Ptr{Void}),
        conf.data, f, p)
end

function f_dbg(c_ctx, level, filename, number, msg)
    jl_ctx = unsafe_pointer_to_objref(c_ctx)
    jl_ctx(level, String(filename), number, String(msg))
    nothing
end

function dbg!(conf::SSLConfig, f)
    conf.dbg = f
    dbg!(conf, c_dbg, pointer_from_objref(f))
    nothing
end

function handshake(ctx::SSLContext)
    @err_check ccall((:mbedtls_ssl_handshake, MBED_TLS), Cint,
        (Ptr{Void},), ctx.data)
    ctx.isopen = true
    nothing
end

function set_alpn!(conf::SSLConfig, protos)
    conf.alpn_protos = protos
    @err_check ccall((:mbedtls_ssl_conf_alpn_protocols, MBED_TLS), Cint,
                     (Ptr{Void}, Ptr{Ptr{Cchar}}), conf.data, protos)
    nothing
end

function alpn_proto(ctx::SSLContext)
    rv = ccall((:mbedtls_ssl_get_alpn_protocol, MBED_TLS), Ptr{Cchar},
               (Ptr{Void},), ctx.data)
    unsafe_string(rv)
end

if Base.VERSION < v"0.5.0-dev+2301"
    import Base: read, write
    const unsafe_read = read
    const unsafe_write = write
    @noinline Base.write(ctx::SSLContext, msg::Base.RefValue{UInt8}) = write(ctx, Base.unsafe_convert(Ptr{UInt8}, msg), UInt(sizeof(UInt8)))
    # the @eval macros are also necessary for this Compat layer to get the symbol name correct for the method
else
    import Base: unsafe_read, unsafe_write
end

@eval function $(Symbol(unsafe_write))(ctx::SSLContext, msg::Ptr{UInt8}, N::UInt)
    nw = 0
    while nw < N
        ret = ccall((:mbedtls_ssl_write, MBED_TLS), Cint,
                    (Ptr{Void}, Ptr{Void}, Csize_t),
                    ctx.data, msg, N - nw)
        ret < 0 && mbed_err(ret)
        nw += ret
        msg += ret
    end
    return Int(nw)
end

Base.write(ctx::SSLContext, msg::UInt8) = write(ctx, Ref(msg))

@eval function $(Symbol(unsafe_read))(ctx::SSLContext, buf::Ptr{UInt8}, nbytes::UInt; err=true)
    nread::UInt = 0
    while nread < nbytes
        n = ccall((:mbedtls_ssl_read, MBED_TLS), Cint,
                  (Ptr{Void}, Ptr{Void}, Csize_t),
                  ctx.data, buf + nread, nbytes - nread)
        if n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || n == 0
            ctx.isopen = false
            err ? throw(EOFError()) : return nread
        end
        if n != MBEDTLS_ERR_SSL_WANT_READ
            n < 0 && mbed_err(n)
            nread += n
        end
    end
end

Base.readbytes!(ctx::SSLContext, buf::Vector{UInt8}, nbytes=length(buf)) = readbytes!(ctx, buf, UInt(nbytes))
function Base.readbytes!(ctx::SSLContext, buf::Vector{UInt8}, nbytes::UInt)
    nr = unsafe_read(ctx, pointer(buf), nbytes; err=false)
    if nr !== nothing
        resize!(buf, nr::UInt)
    else
        nr = nbytes
    end
    return Int(nr::UInt)
end

function Base.readavailable(ctx::SSLContext)
    # For unknown reasons, nb_available on SSLContext erroneously returns 0
    # until `read` is called on the context. As a temporary hack, we read one
    # byte from the SSL context to cause nb_available to be accurate.
    # TODO: figure out and fix the root cause of this
    b = IOBuffer()
    write(b, read(ctx, 1))
    write(b, read(ctx, nb_available(ctx)))
    return takebuf_array(b)
end

function Base.eof(ctx::SSLContext)
    # Not quite semantically correct, since nb_available might still be zero
    # when this returns false (ie, the underlying socket has bytes available but not
    # a complete record)
    nb_available(ctx)>0 && return false
    return eof(ctx.bio)
end

function Base.close(ctx::SSLContext)
    if isopen(ctx.bio)
        try  # This is ugly, but a harmless broken pipe exception will be thrown if the peer closes the connection without responding
            ccall((:mbedtls_ssl_close_notify, MBED_TLS), Cint, (Ptr{Void},), ctx.data)
        catch
        end
        close(ctx.bio)
    end
    ctx.isopen = false
    nothing
end

Base.isopen(ctx::SSLContext) = ctx.isopen && isopen(ctx.bio)

function get_peer_cert(ctx::SSLContext)
    data = ccall((:mbedtls_ssl_get_peer_cert, MBED_TLS), Ptr{Void}, (Ptr{Void},), ctx.data)
    return CRT(data)
end

function get_version(ctx::SSLContext)
    data = ccall((:mbedtls_ssl_get_version, MBED_TLS), Ptr{UInt8}, (Ptr{Void},), ctx.data)
    return unsafe_string(data)
end

function get_ciphersuite(ctx::SSLContext)
    data = ccall((:mbedtls_ssl_get_ciphersuite, MBED_TLS), Ptr{UInt8}, (Ptr{Void},), ctx.data)
    return unsafe_string(data)
end

function Base.nb_available(ctx::SSLContext)
    n = ccall((:mbedtls_ssl_get_bytes_avail, MBED_TLS), Csize_t, (Ptr{Void},), ctx.data)
    return Int(n)
end

function hostname!(ctx::SSLContext, hostname)
    @err_check ccall((:mbedtls_ssl_set_hostname, MBED_TLS), Cint,
      (Ptr{Void}, Cstring), ctx.data, hostname)
end

function __sslinit__()
    global const c_send = cfunction(f_send, Cint, (Ptr{Void}, Ptr{UInt8}, Csize_t))
    global const c_recv = cfunction(f_recv, Cint, (Ptr{Void}, Ptr{UInt8}, Csize_t))
    global const c_dbg = cfunction(f_dbg, Void,
        (Ptr{Void}, Cint, Ptr{UInt8}, Cint, Ptr{UInt8}))
    global const TRUSTED_CERT_FILE = joinpath(dirname(@__FILE__), "../deps/cacert.pem")
end
