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

function sslconnect(dest, port)
    conn = connect(dest, port)
    sslconfig = MbedTLS.SSLConfig(false)
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
    
    @async begin
        (port, server) = listenany(8000)
        @info("listening on port $port")
        put!(trigger, true)
        srvrconn = sslaccept(server, certfile, keyfile)
        inbuff = read(srvrconn, 100)
        @test inbuff == outbuff
        put!(trigger, true)
    end

    take!(trigger)
    @info("connecting to port $port")
    clntconn = sslconnect("127.0.0.1", port)
    @test write(clntconn, outbuff) == 100
    @async begin
        sleep(10)
        put!(trigger, false)
    end

    @test take!(trigger)
end

testclntsrvr(joinpath(dirname(@__FILE__), "test.cert"), joinpath(dirname(@__FILE__), "test.key"))
