mutable struct SSLConfig
    data::Ptr{Cvoid}
    rng
    chain::CRT
    dbg
    cert
    key
    alpn_protos

    function SSLConfig()
        conf = new()
        conf.data = Libc.malloc(1000)  # 360
        ccall((:mbedtls_ssl_config_init, libmbedtls), Cvoid, (Ptr{Cvoid},), conf.data)
        finalizer(conf->begin
            ccall((:mbedtls_ssl_config_free, libmbedtls), Cvoid, (Ptr{Cvoid},), conf.data)
            Libc.free(conf.data)
        end, conf)
        conf
    end
end

Base.show(io::IO, c::SSLConfig) = print(io, "MbedTLS.SSLConfig()")

mutable struct SSLContext <: IO
    data::Ptr{Cvoid}
    datalock::ReentrantLock
    config::SSLConfig
    isopen::Bool
    bio

    function SSLContext()
        ctx = new()
        ctx.data = Libc.malloc(1000)  # 488
        ctx.datalock = ReentrantLock()
        ccall((:mbedtls_ssl_init, libmbedtls), Cvoid, (Ptr{Cvoid},), ctx.data)
        finalizer(ctx->begin
            ccall((:mbedtls_ssl_free, libmbedtls), Cvoid, (Ptr{Cvoid},), ctx.data)
            Libc.free(ctx.data)
        end, ctx)
        ctx
    end
end

macro lockdata(ctx, expr)
    esc(quote
        lock($ctx.datalock)
        @assert $ctx.datalock.reentrancy_cnt == 1
        try
            $expr
        finally
            unlock($ctx.datalock)
        end
    end)
end

function config_defaults!(config::SSLConfig; endpoint=MBEDTLS_SSL_IS_CLIENT,
    transport=MBEDTLS_SSL_TRANSPORT_STREAM, preset=MBEDTLS_SSL_PRESET_DEFAULT)
    @err_check ccall((:mbedtls_ssl_config_defaults, libmbedtls), Cint,
        (Ptr{Cvoid}, Cint, Cint, Cint),
        config.data, endpoint, transport, preset)
end

function authmode!(config::SSLConfig, auth)
    ccall((:mbedtls_ssl_conf_authmode, libmbedtls), Cvoid,
        (Ptr{Cvoid}, Cint),
        config.data, auth)
end

function rng!(config::SSLConfig, f_rng::Ptr{Cvoid}, rng)
    ccall((:mbedtls_ssl_conf_rng, libmbedtls), Cvoid,
        (Ptr{Cvoid}, Ptr{Cvoid}, Any),
        config.data, f_rng, rng)
end

function rng!(config::SSLConfig, rng::AbstractRNG)
    config.rng = rng
    rng!(config, c_rng[], rng)
end

function ca_chain!(config::SSLConfig, chain=crt_parse_file(joinpath(dirname(@__FILE__), "../deps/cacert.pem")))
    config.chain = chain
    ccall((:mbedtls_ssl_conf_ca_chain, libmbedtls), Cvoid,
        (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
        config.data, chain.data, C_NULL)
end

function own_cert!(config::SSLConfig, cert::CRT, key::PKContext)
    config.cert = cert
    config.key = key
    @err_check ccall((:mbedtls_ssl_conf_own_cert, libmbedtls), Cint,
        (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
        config.data, cert.data, key.data)
end

function setup!(ctx::SSLContext, conf::SSLConfig)
    @lockdata ctx begin
        ctx.config = conf
        @err_check ccall((:mbedtls_ssl_setup, libmbedtls), Cint,
            (Ptr{Cvoid}, Ptr{Cvoid}),
            ctx.data, conf.data)
    end
end

function set_bio!(ssl_ctx::SSLContext, ctx, f_send::Ptr{Cvoid}, f_recv::Ptr{Cvoid})
    @lockdata ssl_ctx begin
        ccall((:mbedtls_ssl_set_bio, libmbedtls), Cvoid,
            (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
            ssl_ctx.data, ctx, f_send, f_recv, C_NULL)
    end
end

function f_send(c_ctx, c_msg, sz)
    jl_ctx = unsafe_pointer_to_objref(c_ctx)
    !isopen(jl_ctx.bio) && return Cint(MBEDTLS_ERR_NET_CONN_RESET)
    return Cint(unsafe_write(jl_ctx.bio, c_msg, sz))
end

function f_recv(c_ctx, c_msg, sz)
    jl_ctx = unsafe_pointer_to_objref(c_ctx)
    n = bytesavailable(jl_ctx.bio)
    if n == 0
        return isopen(jl_ctx.bio) ? Cint(MBEDTLS_ERR_SSL_WANT_READ) :
                    jl_ctx.isopen ? Cint(MBEDTLS_ERR_NET_CONN_RESET) :
                                    Cint(n)
    end
    n = min(sz, n)
    unsafe_read(jl_ctx.bio, c_msg, n)
    return Cint(n)
end

function set_bio!(ssl_ctx::SSLContext, jl_ctx::T) where {T<:IO}
    ssl_ctx.bio = jl_ctx
    set_bio!(ssl_ctx, pointer_from_objref(ssl_ctx), c_send[], c_recv[])
    nothing
end

function dbg!(conf::SSLConfig, f::Ptr{Cvoid}, p)
    ccall((:mbedtls_ssl_conf_dbg, libmbedtls), Cvoid,
        (Ptr{Cvoid}, Ptr{Cvoid}, Any),
        conf.data, f, p)
end

function f_dbg(f, level, filename, number, msg)
    f(level, unsafe_string(filename), number, unsafe_string(msg))
    nothing
end

function dbg!(conf::SSLConfig, f)
    conf.dbg = f
    dbg!(conf, c_dbg[], f)
    nothing
end

@enum(DebugThreshold,
    NONE = 0,
    ERROR,
    STATE_CHANGE,
    INFO,
    VERBOSE)

function set_dbg_level(level)
    ccall((:mbedtls_debug_set_threshold, libmbedtls), Cvoid,
        (Cint,), Cint(level))
    nothing
end

Base.wait(ctx::SSLContext) = (eof(ctx.bio); nothing)
                             # eof blocks if the receive buffer is empty

function handshake(ctx::SSLContext)
    while true
        n = @lockdata ctx begin
            ccall((:mbedtls_ssl_handshake, libmbedtls), Cint,
                  (Ptr{Cvoid},), ctx.data)
        end
        if n == 0
            break
        end
        if n != MBEDTLS_ERR_SSL_WANT_READ
            mbed_err(n)
        end
        wait(ctx)
    end
    ctx.isopen = true

    @async while isopen(ctx)
        # Ensure that libuv is reading data from the socket in case the peer
        # has sent a close_notify message on an otherwise idle connection.
        # https://tools.ietf.org/html/rfc5246#section-7.2.1
        Base.start_reading(ctx.bio)
        try
            wait(ctx.bio.readnotify)
        catch e
            if e isa Base.IOError
                # Ignore read errors (IOError ECONNRESET)
                # https://github.com/JuliaWeb/MbedTLS.jl/issues/148
            else
                rethrow(e)
            end
        end
        yield()
    end

    return
end

function set_alpn!(conf::SSLConfig, protos)
    conf.alpn_protos = protos
    @err_check ccall((:mbedtls_ssl_conf_alpn_protocols, libmbedtls), Cint,
                     (Ptr{Cvoid}, Ptr{Ptr{Cchar}}), conf.data, protos)
    nothing
end

function alpn_proto(ctx::SSLContext)
    rv = ccall((:mbedtls_ssl_get_alpn_protocol, libmbedtls), Ptr{Cchar},
               (Ptr{Cvoid},), ctx.data)
    unsafe_string(rv)
end

function Base.unsafe_write(ctx::SSLContext, msg::Ptr{UInt8}, N::UInt)
    nw = 0
    while nw < N
        ret = @lockdata ctx begin
            ccall((:mbedtls_ssl_write, libmbedtls), Cint,
                  (Ptr{Cvoid}, Ptr{Cvoid}, Csize_t),
                  ctx.data, msg, N - nw)
        end
        ret < 0 && mbed_err(ret)
        nw += ret
        msg += ret
    end
    return Int(nw)
end

Base.write(ctx::SSLContext, msg::UInt8) = write(ctx, Ref(msg))

function Base.unsafe_read(ctx::SSLContext, buf::Ptr{UInt8}, nbytes::UInt; err=true)
    nread::UInt = 0
    while nread < nbytes
        n = @lockdata ctx begin
            ccall((:mbedtls_ssl_read, libmbedtls), Cint,
                   (Ptr{Cvoid}, Ptr{Cvoid}, Csize_t),
                   ctx.data, buf + nread, nbytes - nread)
        end
        if n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || n == 0
            close(ctx)
            err ? throw(EOFError()) : return nread
        elseif n == MBEDTLS_ERR_SSL_WANT_READ
            wait(ctx)
        elseif n < 0
            mbed_err(n)
        else
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

Base.readavailable(ctx::SSLContext) = read(ctx, bytesavailable(ctx))

function Base.eof(ctx::SSLContext)
    bytesavailable(ctx)>0 && return false
    return eof(ctx.bio) && bytesavailable(ctx) == 0
end

function Base.close(ctx::SSLContext)
    @lockdata ctx begin
        if isopen(ctx.bio)
            try
                # This is ugly, but a harmless broken pipe exception will be
                # thrown if the peer closes the connection without responding
                ccall((:mbedtls_ssl_close_notify, libmbedtls),
                       Cint, (Ptr{Cvoid},), ctx.data)
            catch
            end
            close(ctx.bio)
        end
        ctx.isopen = false
    end
    nothing
end

function Base.isopen(ctx::SSLContext)

    if !ctx.isopen || !isopen(ctx.bio)
        return false
    end

    decrypt_available_bytes(ctx)

    return ctx.isopen && isopen(ctx.bio)
end

function decrypt_available_bytes(ctx::SSLContext)

    # Zero-byte read causes MbedTLS to call f_recv (always non-blocking)
    # and decrypt any bytes that are already in the LibuvStream read buffer.
    # https://esp32.com/viewtopic.php?t=1101#p4884
    n = @lockdata ctx begin
        ccall((:mbedtls_ssl_read, libmbedtls), Cint,
              (Ptr{Cvoid}, Ptr{Cvoid}, Csize_t),
                 ctx.data,     C_NULL,       0)
    end
    if n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY
        close(ctx)
    elseif n == MBEDTLS_ERR_SSL_WANT_READ
        # ignore
    elseif n < 0
        mbed_err(n)
    end
end

function get_peer_cert(ctx::SSLContext)
    data = ccall((:mbedtls_ssl_get_peer_cert, libmbedtls), Ptr{Cvoid}, (Ptr{Cvoid},), ctx.data)
    return CRT(data)
end

function get_version(ctx::SSLContext)
    if isdefined(ctx, :config)
        data = ccall((:mbedtls_ssl_get_version, libmbedtls), Ptr{UInt8}, (Ptr{Cvoid},), ctx.data)
        return unsafe_string(data)
    else
        throw(ArgumentError("`ctx` hasn't been initialized with an MbedTLS.SSLConfig; run `MbedTLS.setup!(ctx, conf)`"))
    end
end

function get_ciphersuite(ctx::SSLContext)
    data = ccall((:mbedtls_ssl_get_ciphersuite, libmbedtls), Ptr{UInt8}, (Ptr{Cvoid},), ctx.data)
    return unsafe_string(data)
end

function Base.bytesavailable(ctx::SSLContext)

    decrypt_available_bytes(ctx)

    @lockdata ctx begin

        # Now that the bufferd bytes have been processed, find out how many
        # decrypted bytes are available.
        return Int(ccall((:mbedtls_ssl_get_bytes_avail, libmbedtls),
                         Csize_t, (Ptr{Cvoid},), ctx.data))
    end
end

function hostname!(ctx::SSLContext, hostname)
    @err_check ccall((:mbedtls_ssl_set_hostname, libmbedtls), Cint,
      (Ptr{Cvoid}, Cstring), ctx.data, hostname)
end

Sockets.getsockname(ctx::SSLContext) = Sockets.getsockname(ctx.bio)

const c_send = Ref{Ptr{Cvoid}}(C_NULL)
const c_recv = Ref{Ptr{Cvoid}}(C_NULL)
const c_dbg = Ref{Ptr{Cvoid}}(C_NULL)
function __sslinit__()
    c_send[] = @cfunction(f_send, Cint, (Ptr{Cvoid}, Ptr{UInt8}, Csize_t))
    c_recv[] = @cfunction(f_recv, Cint, (Ptr{Cvoid}, Ptr{UInt8}, Csize_t))
    c_dbg[] = @cfunction(f_dbg, Cvoid, (Any, Cint, Ptr{UInt8}, Cint, Ptr{UInt8}))
end
