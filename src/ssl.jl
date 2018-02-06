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
        ccall((:mbedtls_ssl_config_init, MBED_TLS), Cvoid, (Ptr{Cvoid},), conf.data)
        @compat finalizer(conf->begin
            ccall((:mbedtls_ssl_config_free, MBED_TLS), Cvoid, (Ptr{Cvoid},), conf.data)
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
        ccall((:mbedtls_ssl_init, MBED_TLS), Cvoid, (Ptr{Cvoid},), ctx.data)
        @compat finalizer(ctx->begin
            ccall((:mbedtls_ssl_free, MBED_TLS), Cvoid, (Ptr{Cvoid},), ctx.data)
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
    @err_check ccall((:mbedtls_ssl_config_defaults, MBED_TLS), Cint,
        (Ptr{Cvoid}, Cint, Cint, Cint),
        config.data, endpoint, transport, preset)
end

function authmode!(config::SSLConfig, auth)
    ccall((:mbedtls_ssl_conf_authmode, MBED_TLS), Cvoid,
        (Ptr{Cvoid}, Cint),
        config.data, auth)
end

function rng!(config::SSLConfig, f_rng::Ptr{Cvoid}, rng)
    ccall((:mbedtls_ssl_conf_rng, MBED_TLS), Cvoid,
        (Ptr{Cvoid}, Ptr{Cvoid}, Any),
        config.data, f_rng, rng)
end

function rng!(config::SSLConfig, rng::AbstractRNG)
    config.rng = rng
    rng!(config, c_rng[], rng)
end

function ca_chain!(config::SSLConfig, chain=crt_parse_file(joinpath(dirname(@__FILE__), "../deps/cacert.pem")))
    config.chain = chain
    ccall((:mbedtls_ssl_conf_ca_chain, MBED_TLS), Cvoid,
        (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
        config.data, chain.data, C_NULL)
end

function own_cert!(config::SSLConfig, cert::CRT, key::PKContext)
    config.cert = cert
    config.key = key
    @err_check ccall((:mbedtls_ssl_conf_own_cert, MBED_TLS), Cint,
        (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
        config.data, cert.data, key.data)
end

function setup!(ctx::SSLContext, conf::SSLConfig)
    @lockdata ctx begin
        ctx.config = conf
        @err_check ccall((:mbedtls_ssl_setup, MBED_TLS), Cint,
            (Ptr{Cvoid}, Ptr{Cvoid}),
            ctx.data, conf.data)
    end
end

function set_bio!(ssl_ctx::SSLContext, ctx, f_send::Ptr{Cvoid}, f_recv::Ptr{Cvoid})
    @lockdata ssl_ctx begin
        ccall((:mbedtls_ssl_set_bio, MBED_TLS), Cvoid,
            (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
            ssl_ctx.data, ctx, f_send, f_recv, C_NULL)
    end
end

function f_send(c_ctx, c_msg, sz)
    jl_ctx = unsafe_pointer_to_objref(c_ctx)
    jl_msg = unsafe_wrap(Array, c_msg, sz)
    return Cint(write(jl_ctx, jl_msg))
end

function f_recv(c_ctx, c_msg, sz)
    jl_ctx = unsafe_pointer_to_objref(c_ctx)
    jl_msg = unsafe_wrap(Array, c_msg, sz)
    n = readbytes!(jl_ctx, jl_msg, sz)
    return Cint(n)
end

function set_bio!(ssl_ctx::SSLContext, jl_ctx::T) where {T<:IO}
    ssl_ctx.bio = jl_ctx
    set_bio!(ssl_ctx, pointer_from_objref(jl_ctx), c_send[], c_recv[])
    nothing
end

function dbg!(conf::SSLConfig, f::Ptr{Cvoid}, p)
    ccall((:mbedtls_ssl_conf_dbg, MBED_TLS), Cvoid,
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
    ccall((:mbedtls_debug_set_threshold, MBED_TLS), Cvoid,
        (Cint,), Cint(level))
    nothing
end

function handshake(ctx::SSLContext)
    @lockdata ctx begin
        @err_check ccall((:mbedtls_ssl_handshake, MBED_TLS), Cint,
            (Ptr{Cvoid},), ctx.data)
        ctx.isopen = true
    end
    nothing
end

function set_alpn!(conf::SSLConfig, protos)
    conf.alpn_protos = protos
    @err_check ccall((:mbedtls_ssl_conf_alpn_protocols, MBED_TLS), Cint,
                     (Ptr{Cvoid}, Ptr{Ptr{Cchar}}), conf.data, protos)
    nothing
end

function alpn_proto(ctx::SSLContext)
    rv = ccall((:mbedtls_ssl_get_alpn_protocol, MBED_TLS), Ptr{Cchar},
               (Ptr{Cvoid},), ctx.data)
    unsafe_string(rv)
end

import Base: unsafe_read, unsafe_write

function Base.unsafe_write(ctx::SSLContext, msg::Ptr{UInt8}, N::UInt)
    @lockdata ctx begin
        nw = 0
        while nw < N
            ret = ccall((:mbedtls_ssl_write, MBED_TLS), Cint,
                        (Ptr{Cvoid}, Ptr{Cvoid}, Csize_t),
                        ctx.data, msg, N - nw)
            ret < 0 && mbed_err(ret)
            nw += ret
            msg += ret
        end
        return Int(nw)
    end
end

Base.write(ctx::SSLContext, msg::UInt8) = write(ctx, Ref(msg))

function Base.unsafe_read(ctx::SSLContext, buf::Ptr{UInt8}, nbytes::UInt; err=true)
    @lockdata ctx begin
        nread::UInt = 0
        while nread < nbytes
            n = ccall((:mbedtls_ssl_read, MBED_TLS), Cint,
                      (Ptr{Cvoid}, Ptr{Cvoid}, Csize_t),
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

Base.readavailable(ctx::SSLContext) = read(ctx, nb_available(ctx))

function Base.eof(ctx::SSLContext)
    nb_available(ctx)>0 && return false
    return eof(ctx.bio) && nb_available(ctx) == 0
end

function Base.close(ctx::SSLContext)
    @lockdata ctx begin
        if isopen(ctx.bio)
            try
                # This is ugly, but a harmless broken pipe exception will be
                # thrown if the peer closes the connection without responding
                ccall((:mbedtls_ssl_close_notify, MBED_TLS),
                       Cint, (Ptr{Cvoid},), ctx.data)
            catch
            end
            close(ctx.bio)
        end
        ctx.isopen = false
    end
    nothing
end

Base.isopen(ctx::SSLContext) = ctx.isopen && isopen(ctx.bio)

function get_peer_cert(ctx::SSLContext)
    data = ccall((:mbedtls_ssl_get_peer_cert, MBED_TLS), Ptr{Cvoid}, (Ptr{Cvoid},), ctx.data)
    return CRT(data)
end

function get_version(ctx::SSLContext)
    if isdefined(ctx, :config)
        data = ccall((:mbedtls_ssl_get_version, MBED_TLS), Ptr{UInt8}, (Ptr{Cvoid},), ctx.data)
        return unsafe_string(data)
    else
        throw(ArgumentError("`ctx` hasn't been initialized with an MbedTLS.SSLConfig; run `MbedTLS.setup!(ctx, conf)`"))
    end
end

function get_ciphersuite(ctx::SSLContext)
    data = ccall((:mbedtls_ssl_get_ciphersuite, MBED_TLS), Ptr{UInt8}, (Ptr{Cvoid},), ctx.data)
    return unsafe_string(data)
end

function Base.nb_available(ctx::SSLContext)
    @lockdata ctx begin
        # First try to read from the socket and decrypt incoming data if
        # possible. https://esp32.com/viewtopic.php?t=1101#p4884
        ccall((:mbedtls_ssl_read, MBED_TLS),
              Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Csize_t), ctx.data, C_NULL, 0)
        n = ccall((:mbedtls_ssl_get_bytes_avail, MBED_TLS),
                  Csize_t, (Ptr{Cvoid},), ctx.data)
        return Int(n)
    end
end

function hostname!(ctx::SSLContext, hostname)
    @err_check ccall((:mbedtls_ssl_set_hostname, MBED_TLS), Cint,
      (Ptr{Cvoid}, Cstring), ctx.data, hostname)
end

const c_send = Ref{Ptr{Cvoid}}(C_NULL)
const c_recv = Ref{Ptr{Cvoid}}(C_NULL)
const c_dbg = Ref{Ptr{Cvoid}}(C_NULL)
function __sslinit__()
    c_send[] = cfunction(f_send, Cint, Tuple{Ptr{Cvoid}, Ptr{UInt8}, Csize_t})
    c_recv[] = cfunction(f_recv, Cint, Tuple{Ptr{Cvoid}, Ptr{UInt8}, Csize_t})
    c_dbg[] = cfunction(f_dbg, Cvoid, Tuple{Any, Cint, Ptr{UInt8}, Cint, Ptr{UInt8}})
end
