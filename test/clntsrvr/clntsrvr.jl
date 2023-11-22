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
    badsslconfig.chain = MbedTLS.crt_parse(read(badcafile, String))
    try
        clntconn = sslconnect("127.0.0.1", port, badsslconfig)
    catch e
        @test contains(e.msg, "Certificate verification failed")
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

@testset "testverify" begin
    testverify(
        joinpath(@__DIR__, "test.cert"),
        joinpath(@__DIR__, "test.key"),
        joinpath(@__DIR__, "badca.cert"))
end
