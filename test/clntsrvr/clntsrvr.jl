using Test
using Sockets
using MbedTLS

function sslaccept(server, certfile, keyfile)
    sslconfig = MbedTLS.SSLConfig(certfile, keyfile)
    conn = accept(server)
    sslconn = MbedTLS.SSLContext()
    MbedTLS.setup!(sslconn, sslconfig)
    MbedTLS.associate!(sslconn, conn)
    MbedTLS.handshake!(sslconn)
    return sslconn
end

function sslconnect(dest, port, sslconfig = MbedTLS.SSLConfig(false))
    conn = connect(dest, port)
    sslconn = MbedTLS.SSLContext()
    MbedTLS.setup!(sslconn, sslconfig)
    MbedTLS.set_bio!(sslconn, conn)
    MbedTLS.handshake!(sslconn)
    return sslconn
end     

function testclntsrvr(certfile, keyfile)
    outbuff = ones(UInt8, 100) * UInt8(65)
    trigger = Channel{Bool}(1)
    port = UInt16(0)
    local clntconn, srvrconn

    # setup a watchdog kill-switch
    t = Timer(10) do t
        @isdefined(clntconn) && close(clntconn)
        @isdefined(srvrconn) && close(srvrconn)
        close(trigger)
        @test "test failed to complete within timeout"
    end

    (port, server) = listenany(8000)
    @info("listening on port $port")

    r = @async begin
        srvrconn = sslaccept(server, certfile, keyfile)
        close(server)
        @test readline(srvrconn) == "hello"
        inbuff = read(srvrconn, 100)
        @test inbuff == outbuff
        put!(trigger, true)
        inbuff2 = read(srvrconn, 1000)
        @test inbuff2 == outbuff
        put!(trigger, true)
        close(srvrconn)
    end
    bind(trigger, r)

    @info("connecting to port $port")
    clntconn = sslconnect("127.0.0.1", port)
    @test MbedTLS.alpn_proto(clntconn) === nothing
    @test sprint(show, MbedTLS.get_peer_cert(clntconn)) == sprint(show, MbedTLS.crt_parse_file(certfile))
    @test write(clntconn, "hello\n") == 6
    @test write(clntconn, outbuff) == 100
    @test take!(trigger)
    outbuff .*= 2
    @test write(clntconn, outbuff) == 100
    close(clntconn)
    @test take!(trigger)
    wait(r)

    close(t)
end

function testverify(certfile, keyfile, badcafile)
    outbuff = ones(UInt8, 100) * UInt8(65)
    trigger = Channel{Bool}(1)
    port = UInt16(0)
    local clntconn, srvrconn

    # setup a watchdog kill-switch
    t = Timer(10) do t
        @isdefined(clntconn) && close(clntconn)
        @isdefined(srvrconn) && close(srvrconn)
        close(trigger)
        @test "test failed to complete within timeout"
    end

    (port, server) = listenany(8000)
    @info("listening on port $port")

    r = @async begin
        try
            srvrconn = sslaccept(server, certfile, keyfile)
            close(server)
        catch e
        end
        put!(trigger, true)
        @isdefined(srvrconn) && close(srvrconn)
    end
    bind(trigger, r)

    @info("connecting to port $port")
    badsslconfig = MbedTLS.SSLConfig(true)
    MbedTLS.ca_chain!(badsslconfig, MbedTLS.crt_parse(read(badcafile, String)))
    try
        clntconn = sslconnect("127.0.0.1", port, badsslconfig)
    catch e
        @test contains(e.msg, "Certificate verification failed") || contains(e.msg, "SSL - Attempt to verify a certificate without an expected hostname. This is usually insecure.")
    end
    if @isdefined(clntconn)
        close(clntconn)
        @test "No exception raised for certificate verification failure"
    end
    @test take!(trigger)
    wait(r)

    close(t)
end

@testset "testclntsrvr" begin
    testclntsrvr(
        joinpath(@__DIR__, "test.cert"),
        joinpath(@__DIR__, "test.key"))
end

# Sets the ALPN protocols of `conf` to copies of `names`, which only `conf` keeps alive.
@noinline set_alpn_copies!(conf, names) = MbedTLS.set_alpn!(conf, [string(n) for n in names])

@testset "alpn" begin
    certfile = joinpath(@__DIR__, "test.cert")
    keyfile = joinpath(@__DIR__, "test.key")
    srvrconfig = MbedTLS.SSLConfig(certfile, keyfile)
    set_alpn_copies!(srvrconfig, ("http/1.1", "h2"))
    clntconfig = MbedTLS.SSLConfig(false)
    # A `SubString` isn't NUL-terminated where it ends.
    MbedTLS.set_alpn!(clntconfig, split("h2,x", ","))
    # mbedtls keeps the protocol list that `set_alpn!` hands it; it must survive a GC.
    GC.gc()
    garbage = [zeros(UInt8, 16) for _ in 1:100_000]
    GC.gc()
    (port, server) = listenany(8000)
    r = @async begin
        srvrconn = MbedTLS.SSLContext()
        MbedTLS.setup!(srvrconn, srvrconfig)
        MbedTLS.associate!(srvrconn, accept(server))
        MbedTLS.handshake!(srvrconn)
        srvrconn
    end
    clntconn = sslconnect("127.0.0.1", port, clntconfig)
    srvrconn = fetch(r)
    @test MbedTLS.alpn_proto(clntconn) == "h2"
    @test MbedTLS.alpn_proto(srvrconn) == "h2"
    # A connection points into the list it negotiated with, and mbedtls keeps the current
    # list when it rejects a new one; both must survive a GC.
    set_alpn_copies!(srvrconfig, ("http/1.1",))
    @test_throws MbedTLS.MbedException MbedTLS.set_alpn!(clntconfig, [""])
    @test_throws ArgumentError MbedTLS.set_alpn!(clntconfig, String[])
    for _ in 1:3
        garbage = [string("Z", i % 10) for i in 1:100_000]
        GC.gc()
    end
    @test MbedTLS.alpn_proto(clntconn) == "h2"
    @test MbedTLS.alpn_proto(srvrconn) == "h2"
    close(clntconn)
    close(srvrconn)
    close(server)
end

# Any `IO` can carry TLS, not just a `LibuvStream`.
mutable struct ForwardingIO <: IO
    io::TCPSocket
end
for f in (:isopen, :isreadable, :eof, :bytesavailable, :close)
    @eval Base.$f(x::ForwardingIO) = $f(x.io)
end
Base.unsafe_read(x::ForwardingIO, p::Ptr{UInt8}, n::UInt) = unsafe_read(x.io, p, n)
Base.unsafe_write(x::ForwardingIO, p::Ptr{UInt8}, n::UInt) = unsafe_write(x.io, p, n)

@testset "custom bio" begin
    (port, server) = listenany(8000)
    r = @async begin
        srvrconn = sslaccept(server, joinpath(@__DIR__, "test.cert"), joinpath(@__DIR__, "test.key"))
        close(server)
        msg = read(srvrconn, 5)
        write(srvrconn, msg)
        close(srvrconn)
    end
    clntconn = MbedTLS.SSLContext()
    MbedTLS.setup!(clntconn, MbedTLS.SSLConfig(false))
    MbedTLS.set_bio!(clntconn, ForwardingIO(connect("127.0.0.1", port)))
    MbedTLS.handshake!(clntconn)
    write(clntconn, "hello")
    @test String(read(clntconn, 5)) == "hello"
    close(clntconn)
    wait(r)
end

@testset "read to end" begin
    data = rand(UInt8, 50_000)
    (port, server) = listenany(8000)
    r = @async begin
        srvrconn = sslaccept(server, joinpath(@__DIR__, "test.cert"), joinpath(@__DIR__, "test.key"))
        close(server)
        write(srvrconn, data)
        close(srvrconn)
    end
    clntconn = sslconnect("127.0.0.1", port)
    @test read(clntconn) == data
    wait(r)
    close(clntconn)

    buf = UInt8[]
    (port, server) = listenany(8000)
    r = @async begin
        srvrconn = sslaccept(server, joinpath(@__DIR__, "test.cert"), joinpath(@__DIR__, "test.key"))
        close(server)
        write(srvrconn, "hello")
        close(srvrconn)
    end
    clntconn = sslconnect("127.0.0.1", port)
    @test readbytes!(clntconn, buf, 100) == 5
    @test buf[1:5] == b"hello"
    wait(r)
    close(clntconn)
end

function tlspair()
    (port, server) = listenany(8000)
    r = @async sslaccept(server, joinpath(@__DIR__, "test.cert"), joinpath(@__DIR__, "test.key"))
    clntconn = sslconnect("127.0.0.1", port)
    srvrconn = fetch(r)
    close(server)
    return clntconn, srvrconn
end

@testset "end of stream" begin
    # Reads after the end of the stream return nothing, as on a socket.
    clntconn, srvrconn = tlspair()
    write(srvrconn, "abc")
    close(srvrconn)
    @test read(clntconn, 5) == b"abc"
    @test eof(clntconn)
    @test readbytes!(clntconn, zeros(UInt8, 5)) == 0
    @test readavailable(clntconn) == UInt8[]
    @test read(clntconn, 5) == UInt8[]
    close(clntconn)

    # Empty application-data records in a row are not the end of the stream.
    for nempty in 1:3
        clntconn, srvrconn = tlspair()
        for _ in 1:nempty
            @test MbedTLS.ssl_write(srvrconn, Ptr{UInt8}(C_NULL), 0) == 0
        end
        write(srvrconn, "hello")
        @test String(read(clntconn, 5)) == "hello"
        close(clntconn)
        close(srvrconn)
    end

    # `close` doesn't throw when the peer has reset the connection.
    clntconn, srvrconn = tlspair()
    write(clntconn, "request")
    sleep(0.2)
    close(srvrconn.bio)  # unread data makes this close send a reset
    sleep(0.2)
    @test close(clntconn) === nothing
    @test !isopen(clntconn.bio)
end

@testset "read Char" begin
    clntconn, srvrconn = tlspair()
    write(srvrconn, "é!€x")
    @test read(clntconn, Char) == 'é'
    @test read(clntconn, Char) == '!'
    @test readuntil(clntconn, 'x') == "€"
    close(clntconn)
    close(srvrconn)
end

@testset "own_cert! twice" begin
    certfile = joinpath(@__DIR__, "test.cert")
    keyfile = joinpath(@__DIR__, "test.key")
    srvrconfig = MbedTLS.SSLConfig(certfile, keyfile)
    first_freed = Ref(false)
    finalizer(_ -> (first_freed[] = true), srvrconfig.cert)
    MbedTLS.own_cert!(srvrconfig, MbedTLS.crt_parse_file(certfile), MbedTLS.parse_keyfile(keyfile))
    # mbedtls keeps both pairs, so the first must survive a GC.
    GC.gc(); GC.gc()
    @test !first_freed[]
    (port, server) = listenany(8000)
    r = @async begin
        srvrconn = MbedTLS.SSLContext()
        MbedTLS.setup!(srvrconn, srvrconfig)
        MbedTLS.associate!(srvrconn, accept(server))
        MbedTLS.handshake!(srvrconn)
        srvrconn
    end
    clntconn = sslconnect("127.0.0.1", port)
    close(fetch(r))
    close(clntconn)
    close(server)
end

@testset "isreadable while another task waits in eof" begin
    for renegotiation in (false, true)
        srvrconfig = MbedTLS.SSLConfig(joinpath(@__DIR__, "test.cert"), joinpath(@__DIR__, "test.key"))
        clntconfig = MbedTLS.SSLConfig(false)
        renegotiation && MbedTLS.ssl_conf_renegotiation!(clntconfig, MbedTLS.MBEDTLS_SSL_RENEGOTIATION_ENABLED)
        (port, server) = listenany(8000)
        t = @async begin
            s = MbedTLS.SSLContext()
            MbedTLS.setup!(s, srvrconfig)
            MbedTLS.associate!(s, accept(server))
            MbedTLS.handshake!(s)
            s
        end
        clntconn = sslconnect("127.0.0.1", port, clntconfig)
        srvrconn = fetch(t)
        close(server)
        # One record, sent in two parts.
        MbedTLS.@lockdata srvrconn ccall((:mbedtls_ssl_write, MbedTLS.libmbedtls), Cint,
                                         (Ptr{Cvoid}, Ptr{UInt8}, Csize_t), srvrconn.data, "hello", 5)
        record = copy(srvrconn.sendbio.pending)
        empty!(srvrconn.sendbio.pending)
        reader = @async String(read(clntconn, 5))
        sleep(0.2)
        npolls = Ref(0)
        poller = @async while !istaskdone(reader)
            isreadable(clntconn)  # neither blocks nor takes the reader's record
            npolls[] += 1
            yield()
        end
        write(srvrconn.bio, record[1:3])
        sleep(0.5)
        n = npolls[]
        sleep(0.5)
        @test npolls[] > n
        write(srvrconn.bio, record[4:end])
        @test timedwait(() -> istaskdone(reader), 5.0) === :ok
        @test istaskdone(reader) && fetch(reader) == "hello"
        close(clntconn)
        close(srvrconn)
    end
end

@testset "read while a write is blocked" begin
    clntconn, srvrconn = tlspair()
    # The server replies without reading the upload, as an HTTP server does with an early
    # error response. The upload fills the socket buffers and blocks.
    write(srvrconn, "early reply")
    writer = @async try write(clntconn, zeros(UInt8, 64 * 1024 * 1024)) catch e; e end
    sleep(1)
    reader = @async String(read(clntconn, 11))
    @test timedwait(() -> istaskdone(reader), 10.0) === :ok
    @test fetch(reader) == "early reply"
    close(srvrconn.bio)  # unblocks the writer
    wait(writer)
    close(clntconn)
end

@testset "write during a renegotiation" begin
    srvrconfig = MbedTLS.SSLConfig(joinpath(@__DIR__, "test.cert"), joinpath(@__DIR__, "test.key"))
    clntconfig = MbedTLS.SSLConfig(false)
    for conf in (srvrconfig, clntconfig)
        MbedTLS.ssl_conf_renegotiation!(conf, MbedTLS.MBEDTLS_SSL_RENEGOTIATION_ENABLED)
    end
    # With a reader task waiting, it processes the server's reply; without one, the
    # writer does.
    for with_reader in (true, false)
        (port, server) = listenany(8000)
        t = @async begin
            s = MbedTLS.SSLContext()
            MbedTLS.setup!(s, srvrconfig)
            MbedTLS.associate!(s, accept(server))
            MbedTLS.handshake!(s)
            s
        end
        clntconn = sslconnect("127.0.0.1", port, clntconfig)
        srvrconn = fetch(t)
        close(server)
        reader = with_reader ? @async(String(read(clntconn, 5))) : nothing
        # The server asks to renegotiate; the client answers with a ClientHello and must
        # then wait for the server's reply before it can write.
        @test MbedTLS.@lockdata(srvrconn, ccall((:mbedtls_ssl_renegotiate, MbedTLS.libmbedtls),
                                                Cint, (Ptr{Cvoid},), srvrconn.data)) == 0
        MbedTLS.flush_pending(srvrconn)
        sleep(0.2)
        if !with_reader
            eof(clntconn.bio)
            @test isreadable(clntconn)  # processes the request, sending the ClientHello
        end
        writer = @async write(clntconn, "ping")
        sleep(0.2)
        srvr = @async (String(read(srvrconn, 4)), write(srvrconn, "hello"))
        @test timedwait(() -> istaskdone(srvr) && istaskdone(writer), 10.0) === :ok
        @test fetch(writer) == 4
        @test fetch(srvr) == ("ping", 5)
        @test (with_reader ? fetch(reader) : String(read(clntconn, 5))) == "hello"
        close(clntconn)
        close(srvrconn)
    end
end

@testset "write during a renegotiation, with data in flight" begin
    srvrconfig = MbedTLS.SSLConfig(joinpath(@__DIR__, "test.cert"), joinpath(@__DIR__, "test.key"))
    clntconfig = MbedTLS.SSLConfig(false)
    for conf in (srvrconfig, clntconfig)
        MbedTLS.ssl_conf_renegotiation!(conf, MbedTLS.MBEDTLS_SSL_RENEGOTIATION_ENABLED)
    end
    (port, server) = listenany(8000)
    t = @async begin
        s = MbedTLS.SSLContext()
        MbedTLS.setup!(s, srvrconfig)
        MbedTLS.associate!(s, accept(server))
        MbedTLS.handshake!(s)
        s
    end
    clntconn = sslconnect("127.0.0.1", port, clntconfig)
    srvrconn = fetch(t)
    close(server)
    # The server asks to renegotiate and keeps sending data.
    @test MbedTLS.@lockdata(srvrconn, ccall((:mbedtls_ssl_renegotiate, MbedTLS.libmbedtls),
                                            Cint, (Ptr{Cvoid},), srvrconn.data)) == 0
    MbedTLS.flush_pending(srvrconn)
    write(srvrconn, "A")
    write(srvrconn, "B")
    sleep(0.2)
    # The client's reader takes "A" and pauses, so the writer meets "B" while it waits for
    # the server's reply to its ClientHello.
    go = Channel{Nothing}(1)
    reader = @async begin
        a = String(read(clntconn, 1))
        take!(go)
        a * String(read(clntconn, 2))
    end
    sleep(0.2)
    writer = @async write(clntconn, "ping")
    sleep(0.3)
    put!(go, nothing)
    srvr = @async (String(read(srvrconn, 4)), write(srvrconn, "C"))
    done = timedwait(() -> istaskdone(writer) && istaskdone(reader) && istaskdone(srvr), 10.0)
    @test done === :ok
    if done === :ok
        @test fetch(writer) == 4
        @test fetch(reader) == "ABC"
        @test fetch(srvr) == ("ping", 1)
    end
    close(clntconn)
    close(srvrconn)
end

# A TCP socket whose writes return `delay` seconds after the data is sent, as when the
# writer's thread is busy.
mutable struct SlowWriteIO <: IO
    io::TCPSocket
    delay::Float64
end
for f in (:isopen, :isreadable, :eof, :bytesavailable, :close)
    @eval Base.$f(x::SlowWriteIO) = $f(x.io)
end
Base.unsafe_read(x::SlowWriteIO, p::Ptr{UInt8}, n::UInt) = unsafe_read(x.io, p, n)
function Base.unsafe_write(x::SlowWriteIO, p::Ptr{UInt8}, n::UInt)
    r = unsafe_write(x.io, p, n)
    x.delay > 0 && sleep(x.delay)
    return r
end

@testset "write during a renegotiation a reader finishes" begin
    srvrconfig = MbedTLS.SSLConfig(joinpath(@__DIR__, "test.cert"), joinpath(@__DIR__, "test.key"))
    clntconfig = MbedTLS.SSLConfig(false)
    for conf in (srvrconfig, clntconfig)
        MbedTLS.ssl_conf_renegotiation!(conf, MbedTLS.MBEDTLS_SSL_RENEGOTIATION_ENABLED)
    end
    (port, server) = listenany(8000)
    t = @async begin
        s = MbedTLS.SSLContext()
        MbedTLS.setup!(s, srvrconfig)
        MbedTLS.associate!(s, accept(server))
        MbedTLS.handshake!(s)
        s
    end
    bio = SlowWriteIO(connect("127.0.0.1", port), 0.0)
    clntconn = MbedTLS.SSLContext()
    MbedTLS.setup!(clntconn, clntconfig)
    MbedTLS.set_bio!(clntconn, bio)
    MbedTLS.handshake!(clntconn)
    srvrconn = fetch(t)
    close(server)
    @test MbedTLS.@lockdata(srvrconn, ccall((:mbedtls_ssl_renegotiate, MbedTLS.libmbedtls),
                                            Cint, (Ptr{Cvoid},), srvrconn.data)) == 0
    MbedTLS.flush_pending(srvrconn)
    sleep(0.2)
    eof(clntconn.bio)
    @test isreadable(clntconn)  # sends the ClientHello
    srvr = @async String(read(srvrconn, 4))
    sleep(0.2)
    srvrwriter = @async write(srvrconn, "hello")  # sent once the renegotiation is done
    sleep(0.1)
    # The writer processes the server's reply and sends its Finished, but its write returns
    # late; meanwhile a reader processes the server's Finished and reads "hello".
    bio.delay = 0.5
    writer = @async write(clntconn, "ping")
    sleep(0.05)
    bio.delay = 0.0
    reader = @async String(read(clntconn, 5))
    done = timedwait(() -> all(istaskdone, (writer, reader, srvr, srvrwriter)), 10.0)
    @test done === :ok
    if done === :ok
        @test fetch(writer) == 4
        @test fetch(reader) == "hello"
        @test fetch(srvr) == "ping"
    end
    close(clntconn)
    close(srvrconn)
end

@testset "testverify" begin
    testverify(
        joinpath(@__DIR__, "test.cert"),
        joinpath(@__DIR__, "test.key"),
        joinpath(@__DIR__, "badca.cert"))
end
