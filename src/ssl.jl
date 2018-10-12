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
    bio

    function SSLContext()
        ctx = new()
        ctx.data = Libc.malloc(1000)  # 488
        ctx.datalock = ReentrantLock()
        ccall((:mbedtls_ssl_init, libmbedtls), Cvoid, (Ptr{Cvoid},), ctx.data)
        @compat finalizer(ctx->begin
            ccall((:mbedtls_ssl_free, libmbedtls), Cvoid, (Ptr{Cvoid},), ctx.data)
            Libc.free(ctx.data)
        end, ctx)
        ctx
    end
end


# Handshake

function handshake(ctx::SSLContext)

    ctx.isopen && throw(ArgumentError("handshake() already done!"))

    while true
        n = ssl_handshake(ctx)
        if n == 0
            break
        elseif n == MBEDTLS_ERR_SSL_WANT_READ
            if eof(ctx.bio)
                throw(EOFError())
            end
        else
            ssl_abandon(ctx)
            throw(MbedException(n))
        end
    end
    ctx.isopen = true

    @static if VERSION < v"0.7.0-alpha.0"
        @schedule while isopen(ctx)
            # Ensure that libuv is reading data from the socket in case the peer
            # has sent a close_notify message on an otherwise idle connection.
            # https://tools.ietf.org/html/rfc5246#section-7.2.1
            Base.start_reading(ctx.bio)
            try
                wait(ctx.bio.readnotify)
            catch e
                if e isa Base.UVError
                    # Ignore read errors (UVError ECONNRESET)
                    # https://github.com/JuliaWeb/MbedTLS.jl/issues/148
                else
                    rethrow(e)
                end
            end
            yield()
        end
    else
        @async while isopen(ctx)
            # Ensure that libuv is reading data from the socket in case the peer
            # has sent a close_notify message on an otherwise idle connection.
            # https://tools.ietf.org/html/rfc5246#section-7.2.1
            Base.start_reading(ctx.bio)
            try
                wait(ctx.bio.readnotify)
            catch e
                if e isa Base.UVError
                    # Ignore read errors (UVError ECONNRESET)
                    # https://github.com/JuliaWeb/MbedTLS.jl/issues/148
                else
                    rethrow(e)
                end
            end
            yield()
        end
    end

    return
end


# Fatal Errors

"""
The documentation for `ssl_read`, `ssl_write` and `ssl_close_notify` all say:

> If this function returns something other than 0 or
> MBEDTLS_ERR_SSL_WANT_READ/WRITE, you must stop using the SSL context
> for reading or writing, and either free it or call

This function ensures that the `SSLContext` is won't be used again.
"""
function ssl_abandon(ctx::SSLContext)
    ctx.isopen = false
    close(ctx.bio)
end


# Base ::IO Connection State Methods

"""
True unless:
 - TLS `close_notify` was received, or
 - the peer closed the connection (and the TLS buffer is empty), or
 - an un-handled exception occurred while reading.
"""
Base.isreadable(ctx::SSLContext) = true

"""
True unless:
 - `close(::SSLContext)` is called, or
 -  the peer closed the connection.
"""
Base.iswritable(ctx::SSLContext) = ctx.isopen && isopen(ctx.bio)

"""
Same as `iswritable(ctx)`.
> "...a closed stream may still have data to read in its buffer,
>  use eof to check for the ability to read data." [?Base.isopen]
"""
function Base.isopen(ctx::SSLContext)

    if !ctx.isopen || !isopen(ctx.bio)
        return false
    end

    decrypt_available_bytes(ctx)

    return ctx.isopen && isopen(ctx.bio)
end

@static if isdefined(Base, :bytesavailable)
"""
Number of decrypted bytes waiting in the TLS buffer.
"""
Base.bytesavailable(ctx::SSLContext) = _bytesavailable(ctx)
else
Base.nb_available(ctx::SSLContext) = _bytesavailable(ctx)
end

"""
True if not `isreadable` and there are no more `bytesavailable` to read.
"""
function Base.eof(ctx::SSLContext)
    bytesavailable(ctx)>0 && return false
    return eof(ctx.bio) && bytesavailable(ctx) == 0
end

"""
Send a TLS `close_notify` message to the peer.
"""
function Base.close(ctx::SSLContext)

        if isopen(ctx.bio)
            try
                # This is ugly, but a harmless broken pipe exception will be
                # thrown if the peer closes the connection without responding
                ssl_close_notify(ctx)
            catch
            end
            close(ctx.bio)
        end
        ctx.isopen = false
    nothing
end

if isdefined(Compat, :Sockets)
Compat.Sockets.getsockname(ctx::SSLContext) = Compat.Sockets.getsockname(ctx.bio)
end


# Sending Data

"""
Copy `nbytes` from `buf` to `ctx`.

The TLS library function `ssl_write` is called as many times as needed to send
all the data. The TLS library encrypts the data and passes it to the `f_send`
function which sends it to the underlying connection (`ctx.bio`).
See `f_send` and `set_bio!` below.
"""
function ssl_unsafe_write(ctx::SSLContext, buf::Ptr{UInt8}, nbytes::UInt)

    iswritable(ctx) ||
    throw(ArgumentError("`unsafe_write` requires `iswritable(::SSLContext)`"))

    nwritten = 0
    while nwritten < nbytes
        n = ssl_write(ctx, buf + nwritten, nbytes - nwritten)
        if n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE
            @assert false "Should not get to here because `f_send` " *
                          "never returns ...WANT_READ/WRITE."
            yield()
            continue
        elseif n == MBEDTLS_ERR_NET_CONN_RESET
            ssl_abandon(ctx)
            Base.check_open(ctx.bio)
            @assert false
        elseif n < 0
            ssl_abandon(ctx)
            throw(MbedException(n))
        end
        nwritten += n
    end
    return Int(nwritten)
end


# Sending Encrypted Data

"""
Copy `nbytes` of encrypted data from `buf` to the underlying `bio` connection.
"""
function f_send(c_ctx, c_msg, sz)
    jl_ctx = unsafe_pointer_to_objref(c_ctx)
    !isopen(jl_ctx.bio) && return Cint(MBEDTLS_ERR_NET_CONN_RESET)
    return Cint(unsafe_write(jl_ctx.bio, c_msg, sz))
end

"""
Connect `f_send` and `f_recv` callback functions to `SSLContext`.
"""
function set_bio!(ssl_ctx::SSLContext, jl_ctx::T) where {T<:IO}
    ssl_ctx.bio = jl_ctx
    set_bio!(ssl_ctx, pointer_from_objref(ssl_ctx), c_send[], c_recv[])
    nothing
end


# Receiving Data

function ssl_unsafe_read(ctx::SSLContext, buf::Ptr{UInt8}, nbytes::UInt)

    isreadable(ctx) ||
    throw(ArgumentError("`ssl_unsafe_read` requires `isreadable(::SSLContext)`"))

    nread::UInt = 0
    try
        while true

            n = ssl_read(ctx, buf + nread, nbytes - nread)

            if n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ||
               n == MBEDTLS_ERR_NET_CONN_RESET
                ssl_abandon(ctx)
                @assert ssl_get_bytes_avail(ctx) == 0   #FIXME remove this
                @assert ssl_check_pending(ctx) == false #FIXME remove this
                return nread
            elseif n == MBEDTLS_ERR_SSL_WANT_READ
                @assert ssl_get_bytes_avail(ctx) == 0   #FIXME remove this
                return nread
            elseif n < 0
                ssl_abandon(ctx)
                throw(MbedException(n))
            end

            nread += n
            @assert nread <= nbytes

            if nread == nbytes
                return nread
            end
        end
    catch e
        ssl_abandon(ctx)
        rethrow(e)
    end

    @assert false "unreachable"
end



# Receiving Encrypted Data

"""
Copy at most `nbytes` of encrypted data to `buf` from the `bio` connection.
If no encrypted bytes are available return:
 - `MBEDTLS_ERR_SSL_WANT_READ` if the connection is still open, or
 - `MBEDTLS_ERR_NET_CONN_RESET` if it is closed.
"""
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


# Base ::IO Write Methods

Base.unsafe_write(ctx::SSLContext, msg::Ptr{UInt8}, N::UInt) =
    ssl_unsafe_write(ctx, msg, N)

Base.write(ctx::SSLContext, msg::UInt8) = write(ctx, Ref(msg))


# Base ::IO Read Methods

"""
Copy `nbytes` of decrypted data from `ctx` into `buf`.
Wait for sufficient decrypted data to be available.
Throw `EOFError` if the peer sends TLS `close_notify` or closes the
connection before `nbytes` have been copied.
"""
function Base.unsafe_read(ctx::SSLContext, buf::Ptr{UInt8}, nbytes::UInt)
    nread = 0
    while nread < nbytes
        if eof(ctx)
            throw(EOFError())
        end
        nread += ssl_unsafe_read(ctx, buf + nread, nbytes - nread)
    end
    nothing
end

"""
Copy at most `nbytes` of decrypted data from `ctx` into `buf`.
If `all=true`: wait for sufficient decrypted data to be available.
Less than `nbytes` may be copied if the peer sends TLS `close_notify` or closes
the connection.
Returns number of bytes copied into `buf` (`<= nbytes`).
"""
Base.readbytes!(ctx::SSLContext, buf::Vector{UInt8}, nbytes=length(buf); kw...) =
    readbytes!(ctx, buf, UInt(nbytes); kw...)

function Base.readbytes!(ctx::SSLContext, buf::Vector{UInt8}, nbytes::UInt;
                         all::Bool=true)
    nbytes <= length(buf) || throw(ArgumentError("`buf` too small!"))
    nread = 0
    while nread < nbytes
        nread += ssl_unsafe_read(ctx, pointer(buf) + nread, nbytes - nread)
        if !all || eof(ctx)
            break
        end
    end
    return nread
end

"""
Read available decrypted data from `ctx`,
but don't wait for more data to arrive.

The amount of decrypted data that can be read at once is limited by
`MBEDTLS_SSL_MAX_CONTENT_LEN`.
"""
function Base.readavailable(ctx::SSLContext)
    n = UInt(MBEDTLS_SSL_MAX_CONTENT_LEN)
    buf = Vector{UInt8}(#=undef,=# n)
    n = ssl_unsafe_read(ctx, pointer(buf), n)
    return resize!(buf, n)
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
    ctx.config = conf
    ssl_setup(ctx, conf)
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


# C API

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

function ssl_setup(ctx::SSLContext, conf::SSLConfig)
    @lockdata ctx begin
        @err_check ccall((:mbedtls_ssl_setup, libmbedtls), Cint,
            (Ptr{Cvoid}, Ptr{Cvoid}),
            ctx.data, conf.data)
    end
end

function ssl_handshake(ctx::SSLContext)
    n = @lockdata ctx begin
        ccall((:mbedtls_ssl_handshake, libmbedtls), Cint,
              (Ptr{Cvoid},), ctx.data)
    end
end

"""
Return the number of application data bytes remaining to be read
from the current record.

https://tls.mbed.org/api/ssl_8h.html#ad43142085f3182e9b0dc967ec582032b:
"""
function ssl_get_bytes_avail(ctx::SSLContext)::Int
    @lockdata ctx begin
        return ccall((:mbedtls_ssl_get_bytes_avail, libmbedtls),
                     Csize_t, (Ptr{Cvoid},), ctx.data)
    end
end

"""
    ssl_check_pending(::SSLContext)::Bool

Check if there is data already read from the underlying transport
but not yet processed.

If the SSL/TLS module successfully returns from an operation - e.g.
a handshake or an application record read - and you're awaiting
incoming data next, you must not immediately idle on the underlying
transport to have data ready, but you need to check the value of
this function first.  The reason is that the desired data might
already be read but not yet processed.  If, in contrast, a previous
call to the SSL/TLS module returned MBEDTLS_ERR_SSL_WANT_READ, it
is not necessary to call this function, as the latter error code
entails that all internal data has been processed.

https://tls.mbed.org/api/ssl_8h.html#a4075f7de9877fd667bcfa2e819e33426
"""
function ssl_check_pending(ctx::SSLContext)::Bool
    @lockdata ctx begin
	return ccall((:mbedtls_ssl_check_pending, libmbedtls),
		     Cint, (Ptr{Cvoid},), ctx.data) > 0
    end
end

function set_bio!(ssl_ctx::SSLContext, ctx, f_send::Ptr{Cvoid}, f_recv::Ptr{Cvoid})
    @lockdata ssl_ctx begin
        ccall((:mbedtls_ssl_set_bio, libmbedtls), Cvoid,
            (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
            ssl_ctx.data, ctx, f_send, f_recv, C_NULL)
    end
end

"""
    ssl_read(::SSLContext, ptr, n)

Returns One of the following:
0 if the read end of the underlying transport was closed,
the (positive) number of bytes read, or
a negative error code on failure.

If MBEDTLS_ERR_SSL_WANT_READ is returned, no application data is
available from the underlying transport. In this case, the function
needs to be called again at some later stage.


If this function returns something other than a positive value or
MBEDTLS_ERR_SSL_WANT_READ/WRITE or MBEDTLS_ERR_SSL_CLIENT_RECONNECT,
you must stop using the SSL context for reading or writing, and
either free it or call mbedtls_ssl_session_reset() on it before
re-using it for a new connection; the current connection must be
closed.

https://tls.mbed.org/api/ssl_8h.html#aa2c29eeb1deaf5ad9f01a7515006ede5
"""
function ssl_read(ctx::SSLContext, ptr, n)::Int
    @lockdata ctx begin
        return ccall((:mbedtls_ssl_read, libmbedtls), Cint,
                     (Ptr{Cvoid}, Ptr{Cvoid}, Csize_t),
                     ctx.data, ptr, n)
    end
end

"""
    ssl_write(::SSLContext, ptr, n)

When this function returns MBEDTLS_ERR_SSL_WANT_WRITE/READ, it must
be called later with the same arguments, until it returns a value
greater that or equal to 0. When the function returns
MBEDTLS_ERR_SSL_WANT_WRITE there may be some partial data in the
output buffer, however this is not yet sent.

If this function returns something other than 0, a positive value
or MBEDTLS_ERR_SSL_WANT_READ/WRITE, you must stop using the SSL
context for reading or writing, and either free it or call
mbedtls_ssl_session_reset() on it before re-using it for a new
connection; the current connection must be closed.

https://tls.mbed.org/api/ssl_8h.html#a5bbda87d484de82df730758b475f32e5
"""
function ssl_write(ctx::SSLContext, ptr, n)::Int
    @lockdata ctx begin
        return ccall((:mbedtls_ssl_write, libmbedtls), Cint,
                     (Ptr{Cvoid}, Ptr{Cvoid}, Csize_t),
                     ctx.data, ptr, n)
    end
end

"""
    ssl_close_notify(::SSLContext)

Notify the peer that the connection is being closed.
0 if successful, or a specific SSL error code.

If this function returns something other than 0 or
MBEDTLS_ERR_SSL_WANT_READ/WRITE, you must stop using the SSL context
for reading or writing, and either free it or call
mbedtls_ssl_session_reset() on it before re-using it for a new
connection; the current connection must be closed.

https://tls.mbed.org/api/ssl_8h.html#ac2c1b17128ead2df3082e27b603deb4c
"""
function ssl_close_notify(ctx::SSLContext)
    @lockdata ctx begin
        return ccall((:mbedtls_ssl_close_notify, libmbedtls),
                     Cint, (Ptr{Cvoid},), ctx.data)
    end
end

function _bytesavailable(ctx::SSLContext)

    decrypt_available_bytes(ctx)

    @lockdata ctx begin

        # Now that the bufferd bytes have been processed, find out how many
        # decrypted bytes are available.
        return Int(ccall((:mbedtls_ssl_get_bytes_avail, libmbedtls),
                         Csize_t, (Ptr{Cvoid},), ctx.data))
    end
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

function hostname!(ctx::SSLContext, hostname)
    @err_check ccall((:mbedtls_ssl_set_hostname, libmbedtls), Cint,
      (Ptr{Cvoid}, Cstring), ctx.data, hostname)
end

const c_send = Ref{Ptr{Cvoid}}(C_NULL)
const c_recv = Ref{Ptr{Cvoid}}(C_NULL)
const c_dbg = Ref{Ptr{Cvoid}}(C_NULL)
function __sslinit__()
    c_send[] = @cfunction(f_send, Cint, (Ptr{Cvoid}, Ptr{UInt8}, Csize_t))
    c_recv[] = @cfunction(f_recv, Cint, (Ptr{Cvoid}, Ptr{UInt8}, Csize_t))
    c_dbg[] = @cfunction(f_dbg, Cvoid, (Any, Cint, Ptr{UInt8}, Cint, Ptr{UInt8}))
end
