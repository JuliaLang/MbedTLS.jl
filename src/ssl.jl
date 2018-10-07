# Data Structures

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
        @compat finalizer(conf->begin
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
    close_notify_sent::Bool
    decrypted_data_wanted::Condition
    decrypted_data_ready::Condition
    bio

    function SSLContext()
        ctx = new()
        ctx.data = Libc.malloc(1000)  # 488
        ctx.datalock = ReentrantLock()
        ctx.isopen = false
        ctx.close_notify_sent = false
        ctx.decrypted_data_wanted = Condition()
        ctx.decrypted_data_ready = Condition()
        ccall((:mbedtls_ssl_init, libmbedtls), Cvoid, (Ptr{Cvoid},), ctx.data)
        @compat finalizer(ctx->begin
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


# Configuration

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


# Debug


@static if DEBUG_LEVEL > 0
    using Dates
    taskid(t=current_task()) = string(hash(t) & 0xffff, base=16, pad=4)
    debug_header() = string("MBTLS: ", rpad(Dates.now(), 24), taskid(), " ")
end

macro debug(n::Int, s)
    DEBUG_LEVEL >= n ? :(println(debug_header(), $(esc(s)))) :
                       :()
end

macro 💀(s) :( @debug 1 $(esc(s)) ) end
macro 😬(s) :( @debug 2 $(esc(s)) ) end
macro 🤖(s) :( @debug 3 $(esc(s)) ) end


# Low level Encrypted IO Callbacks

function f_send(c_ctx, c_msg, sz)
    jl_ctx = unsafe_pointer_to_objref(c_ctx)                                    ;@🤖 "f_send ➡️  $sz"
    return Cint(unsafe_write(jl_ctx.bio, c_msg, sz))
end

function f_recv(c_ctx, c_msg, sz)
    @assert sz > 0
    jl_ctx = unsafe_pointer_to_objref(c_ctx)
    n = bytesavailable(jl_ctx.bio)
    if n == 0
        return isopen(jl_ctx.bio) ? Cint(MBEDTLS_ERR_SSL_WANT_READ) :
        !jl_ctx.close_notify_sent ? Cint(MBEDTLS_ERR_NET_CONN_RESET) :
                                    Cint(0)
    end
    n = min(sz, n)                                                              ;@🤖 "f_recv ⬅️  $n"
    unsafe_read(jl_ctx.bio, c_msg, n)
    return Cint(n)
end

function set_bio!(ssl_ctx::SSLContext, jl_ctx::T) where {T<:IO}
    ssl_ctx.bio = jl_ctx
    set_bio!(ssl_ctx, pointer_from_objref(ssl_ctx), c_send[], c_recv[])
    nothing
end


# Debug

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


# Handshake

function handshake(ctx::SSLContext)

    ctx.isopen && throw(ArgumentError("handshake() already done!"))
                                                                                ;@😬 "🤝 ..."
    while true
        n = @lockdata ctx begin
            ccall((:mbedtls_ssl_handshake, libmbedtls), Cint,
                  (Ptr{Cvoid},), ctx.data)
        end
        if n == 0
            break
        end
        if n == MBEDTLS_ERR_SSL_WANT_READ                                       ;@😬 "🤝  ⌛️"
            if eof(ctx.bio)
                throw(EOFError())                                               ;@💀 "🤝  💥"
            end
        else
            mbed_err(n)
        end
    end
                                                                                ;@😬 "🤝  ✅"
    ctx.isopen = true

    @static if VERSION < v"0.7.0-alpha.0"
        @schedule monitor(ctx)
    else
        @async    monitor(ctx)
    end

    return
end


# Connection Monitoring

"""
    monitor(::SSLContext)

For as long as the SSLContext is open:
 - Notify readers (blocked in eof()) when decrypted data is available.
 - Check the TLS buffers for encrypted data that needs to be processed.
   (zero-byte ssl_read(), see https://esp32.com/viewtopic.php?t=1101#p4884)
 - If the peer sends a close_notify message or closes then TCP connection,
   then notify readers and close the SSLContext.
 - Wait for more encrypted data to arrive.

State management:
 - `ctx.isopen` is set `false` when `unsafe_read` or `monitor` throw an error
    or when the `monitor` determines that the peer has closed the connection.
 - `close(::TCPSocket)` is called only at the end of the `monitor` loop.
 - `close(::SSLContext)` just calls `ssl_close_notify`.
"""
function monitor(ctx::SSLContext)

    @assert ctx.isopen

    try
        while ctx.isopen

            n_decrypted = ssl_get_bytes_avail(ctx)                              ;@🤖 "mon 📥  $n_decrypted"
            if n_decrypted > 0
                notify(ctx.decrypted_data_ready);                               ;@🤖 "mon 🗣"
                yield()
            end

            if (n_decrypted == 0 && ssl_check_pending(ctx)) ||  (                @🤖 "mon ⌛️";
                                             !eof(ctx.bio))                     ;@🤖 "mon 👁"
                n = ssl_read(ctx, C_NULL, 0)
                if n == MBEDTLS_ERR_SSL_WANT_READ ||
                   ssl_get_bytes_avail(ctx) > n_decrypted
                    continue                                                    ;@🤖 "mon 🔄"
                elseif n == 0 && n_decrypted > 0                                ;@🤖 "mon 🔔"
                    notify(ctx.decrypted_data_ready)                            ;@🤖 "mon 💤"
                    wait(ctx.decrypted_data_wanted)
                else
                    ctx.isopen = false
                    if n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY
                        notify(ctx.decrypted_data_ready)                        ;@🤖 "mon 🗣  🛑"
                    else
                        notify_error(ctx, MbedException(n))                     ;@🤖 "mon 🗣  💥"
                    end
                end
            end

            if !isopen(ctx.bio);
                ctx.isopen = false                                              ;@🤖 "mon 🗣  🗑"
                notify(ctx.decrypted_data_ready)
            end
        end
    catch e
        ctx.isopen = false                                                      ;@🤖 "mon 💥  $e"
        notify_error(ctx, e)
        rethrow(e)
    finally
        close(ctx.bio)                                                          ;@🤖 "mon 🗑"
    end
end

notify_error(ctx::SSLContext, e) = notify(ctx.decrypted_data_ready, e;
                                          all=true, error=true)


# ALPN Configuration

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


# IO Interface

function Base.unsafe_write(ctx::SSLContext, msg::Ptr{UInt8}, N::UInt)
    nw = 0                                                                      ;@🤖 "ssl_write ➡️  $N"
    while nw < N
        ret = ssl_write(ctx, msg, N - nw)
        ret < 0 && mbed_err(ret)
        nw += ret
        msg += ret
    end
    return Int(nw)
end

Base.write(ctx::SSLContext, msg::UInt8) = write(ctx, Ref(msg))

Base.unsafe_read(ctx::SSLContext, buf::Ptr{UInt8}, nbytes::UInt) =
    (ssl_unsafe_read(ctx, buf, nbytes); nothing)

function ssl_unsafe_read(ctx::SSLContext, buf::Ptr{UInt8}, nbytes::UInt;
                         error_on_close::Bool=true, wait_for_nbytes::Bool=true)
    nread::UInt = 0
    try
        while nread < nbytes

            n = ssl_read(ctx, buf + nread, nbytes - nread)                      ;@😬 "ssl_read ⬅️  $n"

            if n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || n == 0
                ctx.isopen = false                                              ;@😬 "ssl_read 🛑"
                if error_on_close
                    throw(EOFError())
                else
                    break
                end
            elseif n == MBEDTLS_ERR_SSL_WANT_READ
                if wait_for_nbytes;                                             ;@🤖 "ssl_read 🗣"
                    notify(ctx.decrypted_data_wanted)                           ;@😬 "ssl_read ⌛️"
                    wait(ctx.decrypted_data_ready)
                else
                    break
                end
            elseif n < 0
                mbed_err(n)
            else
                nread += n
            end
        end
    catch e
        ctx.isopen = false                                                      ;@💀 "ssl_read 💥"
        rethrow(e)
    end
    return nread
end

Base.readbytes!(ctx::SSLContext, buf::Vector{UInt8}, nbytes=length(buf); kw...) = readbytes!(ctx, buf, UInt(nbytes); kw...)

function Base.readbytes!(ctx::SSLContext, buf::Vector{UInt8}, nbytes::UInt; all::Bool=true)
    nr = ssl_unsafe_read(ctx, pointer(buf), nbytes; error_on_close=false,
                                                    wait_for_nbytes=all)        ;@😬 "readbytes! ⬅️  $nr"
    return Int(nr::UInt)
end

function Base.readavailable(ctx::SSLContext)
    buf = Vector{UInt8}(undef, MBEDTLS_SSL_MAX_CONTENT_LEN)
    nr = ssl_unsafe_read(ctx, pointer(buf), UInt(MBEDTLS_SSL_MAX_CONTENT_LEN);
                         error_on_close=false, wait_for_nbytes=false)           ;@😬 "readavailable ⬅️  $nr"
    return resize!(buf, nr)
end

function Base.eof(ctx::SSLContext)
    while (n = ssl_get_bytes_avail(ctx) == 0)                                   ;@🤖 "eof $n  📥"
        if !ctx.isopen                                                          ;@💀 "eof true"
            return true
        end                                                                     ;@🤖 "eof 🗣"
        notify(ctx.decrypted_data_wanted)                                       ;@😬 "eof ⌛️"
        wait(ctx.decrypted_data_ready)
    end                                                                         ;@😬 "eof false"
    return false
end

function Base.close(ctx::SSLContext)                                            ;@💀 "close isopen=$(ctx.isopen), " *
                                                                                               "$(isopen(ctx.bio))"
    if !ctx.close_notify_sent && ctx.isopen && isopen(ctx.bio)
        ctx.close_notify_sent = true
        # This is ugly, but a harmless broken pipe exception will be
        # thrown if the peer closes the connection without responding
        # FIXME need to reproduce this and handle a specific error.
        # try
            ssl_close_notify(ctx)                                               ;@💀 "close 🗣"
        # catch e
        #     if !(e isa XXX) || e.code != YYY
        #         rethrow(e)
        #     end
        #end
    end
    nothing
end

Base.isopen(ctx::SSLContext) = ctx.isopen && !ctx.close_notify_sent


# C API

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

@static if isdefined(Base, :bytesavailable)
    Base.bytesavailable(ctx::SSLContext) = ssl_get_bytes_avail(ctx)
else
    Base.nb_available(ctx::SSLContext) = ssl_get_bytes_avail(ctx)
end

function ssl_get_bytes_avail(ctx::SSLContext)::Int
    @lockdata ctx begin
        return ccall((:mbedtls_ssl_get_bytes_avail, libmbedtls),
                     Csize_t, (Ptr{Cvoid},), ctx.data)
    end
end

function ssl_check_pending(ctx::SSLContext)::Bool
    @lockdata ctx begin
        return ccall((:mbedtls_ssl_check_pending, libmbedtls),
                     Cint, (Ptr{Cvoid},), ctx.data) > 0
    end
end

function ssl_read(ctx::SSLContext, ptr, n)::Int
    @lockdata ctx begin
        return ccall((:mbedtls_ssl_read, libmbedtls), Cint,
                     (Ptr{Cvoid}, Ptr{Cvoid}, Csize_t),
                     ctx.data, ptr, n)
    end
end

function ssl_write(ctx::SSLContext, ptr, n)::Int
    @lockdata ctx begin
        return ccall((:mbedtls_ssl_write, libmbedtls), Cint,
                     (Ptr{Cvoid}, Ptr{Cvoid}, Csize_t),
                     ctx.data, ptr, n)
    end
end

function ssl_close_notify(ctx::SSLContext)
    @lockdata ctx begin
        return ccall((:mbedtls_ssl_close_notify, libmbedtls),
                     Cint, (Ptr{Cvoid},), ctx.data)
    end
end

function hostname!(ctx::SSLContext, hostname)
    @err_check ccall((:mbedtls_ssl_set_hostname, libmbedtls), Cint,
      (Ptr{Cvoid}, Cstring), ctx.data, hostname)
end

Compat.Sockets.getsockname(ctx::SSLContext) = Compat.Sockets.getsockname(ctx.bio)

const c_send = Ref{Ptr{Cvoid}}(C_NULL)
const c_recv = Ref{Ptr{Cvoid}}(C_NULL)
const c_dbg = Ref{Ptr{Cvoid}}(C_NULL)
function __sslinit__()
    c_send[] = @cfunction(f_send, Cint, (Ptr{Cvoid}, Ptr{UInt8}, Csize_t))
    c_recv[] = @cfunction(f_recv, Cint, (Ptr{Cvoid}, Ptr{UInt8}, Csize_t))
    c_dbg[] = @cfunction(f_dbg, Cvoid, (Any, Cint, Ptr{UInt8}, Cint, Ptr{UInt8}))
end
