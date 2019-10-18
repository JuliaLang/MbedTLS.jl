include("debug.jl")

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
        finalizer(x->begin
            data = x.data
            @async begin
                ccall((:mbedtls_ssl_config_free, libmbedtls),
                      Cvoid, (Ptr{Cvoid},), data)
                Libc.free(data)
            end
        end, conf)
        conf
    end
end

Base.show(io::IO, c::SSLConfig) = print(io, "MbedTLS.SSLConfig()")

mutable struct SSLContext <: IO
    data::Ptr{Cvoid}
    datalock::ReentrantLock
    waitlock::ReentrantLock
    config::SSLConfig
    isreadable::Bool
    bytesavailable::Int
    close_notify_sent::Bool
    async_exception::Union{Nothing,MbedException}
    bio

    function SSLContext()
        ctx = new()
        ctx.data = Libc.malloc(1000)  # 488
        ctx.datalock = ReentrantLock()
        ctx.waitlock = ReentrantLock()
        ctx.isreadable = false
        ctx.bytesavailable = -1
        ctx.close_notify_sent = false
        ctx.async_exception = nothing
        ccall((:mbedtls_ssl_init, libmbedtls), Cvoid, (Ptr{Cvoid},), ctx.data)
        finalizer(x->begin
            data = x.data
            @async begin
                ccall((:mbedtls_ssl_free, libmbedtls),
                      Cvoid, (Ptr{Cvoid},), ctx.data)
                Libc.free(ctx.data)
            end
        end, ctx)
        ctx
    end
end


# Handshake

function handshake(ctx::SSLContext)

    ctx.isreadable && throw(ArgumentError("handshake() already done!"))
                                                                                ;@😬 "🤝 ..."
    while true
        n = ssl_handshake(ctx)
        if n == 0
            break
        elseif n == MBEDTLS_ERR_SSL_WANT_READ                                   ;@😬 "🤝  ⌛️"
            if eof(ctx.bio)
                throw(EOFError())                                               ;@💀 "🤝  🛑"
            end
        else
            ssl_abandon(ctx)                                                    ;@💀 "🤝  💥"
            throw(MbedException(n))
        end
    end
                                                                                ;@😬 "🤝  ✅"
    ctx.isreadable = true
    ctx.bytesavailable = 0
    ctx.close_notify_sent = false

    @async try
        while ctx.isreadable
            wait_for_decrypted_data(ctx)
            while ctx.bytesavailable > 0
                sleep(5)
            end
        end
    catch e
        ctx.async_exception = e
    end

    nothing
end

function check_async_exception(ctx::SSLContext)
    if ctx.async_exception !== nothing
        e = ctx.async_exception
        ctx.async_exception = nothing
        throw(e)
    end
end



# Fatal Errors

"""
The documentation for `ssl_read`, `ssl_write` and `ssl_close_notify` all say:

> If this function returns something other than 0 or
> MBEDTLS_ERR_SSL_WANT_READ/WRITE, you must stop using the SSL context
> for reading or writing, and either free it or call

This function ensures that the `SSLContext` is won't be used again.
"""
function ssl_abandon(ctx::SSLContext)                                           ;@💀 "ssl_abandon 💥"
    ctx.isreadable = false
    ctx.bytesavailable = 0
    ctx.close_notify_sent = true
    close(ctx.bio)
    n = ssl_session_reset(ctx)
    n == 0 || throw(MbedException(n))
end


# Base ::IO Connection State Methods

Sockets.getsockname(ctx::SSLContext) = Sockets.getsockname(ctx.bio)

"""
True unless:
 - TLS `close_notify` was received, or
 - the peer closed the connection (and the TLS buffer is empty), or
 - an un-handled exception occurred while reading.
"""
Base.isreadable(ctx::SSLContext) = ctx.isreadable

"""
True unless:
 - `close(::SSLContext)` is called, or
 -  the peer closed the connection.
"""
Base.iswritable(ctx::SSLContext) = !ctx.close_notify_sent && isopen(ctx.bio)

"""
Same as `iswritable(ctx)`.
> "...a closed stream may still have data to read in its buffer,
>  use eof to check for the ability to read data." [?Base.isopen]
"""
Base.isopen(ctx::SSLContext) = iswritable(ctx)

@static if isdefined(Base, :bytesavailable)
"""
Number of decrypted bytes waiting in the TLS buffer.
"""
Base.bytesavailable(ctx::SSLContext) = ctx.bytesavailable
else
Base.nb_available(ctx::SSLContext) = ctx.bytesavailable
end

"""
True if not `isreadable` and there are no more `bytesavailable` to read.
"""
function Base.eof(ctx::SSLContext)
    if ctx.bytesavailable > 0
        return false
    end                                                                         ;@😬 "eof ⌛️"
    wait_for_decrypted_data(ctx)
    @assert ctx.bytesavailable > 0 || !ctx.isreadable
    return ctx.bytesavailable <= 0
end

"""
Send a TLS `close_notify` message to the peer.
"""
function Base.close(ctx::SSLContext)                                            ;@💀 "close iswritable=$(iswritable(ctx))"

    if iswritable(ctx)

        n = ssl_close_notify(ctx)
        ctx.close_notify_sent = true                                            ;@💀 "close 🗣"

        if n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE    ;@💀 "close ⌛️"
            @assert false "Should not get to here because `f_send` " *
                          "never returns ...WANT_READ/WRITE."
        elseif n != 0
            ssl_abandon(ctx)
            throw(MbedException(n))
        end
    end
    @assert !iswritable(ctx)
    nothing
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

    Base.check_open(ctx.bio) # Throw error if `bio` is closed.

    iswritable(ctx) ||
    throw(ArgumentError("`unsafe_write` requires `iswritable(::SSLContext)`"))

    nwritten = 0                                                                ;@🤖 "ssl_write ➡️  $nbytes"
    while nwritten < nbytes
        n = ssl_write(ctx, buf + nwritten, nbytes - nwritten)
        if n == MBEDTLS_ERR_SSL_WANT_READ || n == MBEDTLS_ERR_SSL_WANT_WRITE    ;@💀 "ssl_write ⌛️"
            @assert false "Should not get to here because `f_send` " *
                          "never returns ...WANT_READ/WRITE."
            yield()
            continue
        elseif n == MBEDTLS_ERR_NET_CONN_RESET
            ssl_abandon(ctx)                                                    ;@🤖 "ssl_write 🛑"
            Base.check_open(ctx.bio)
            @assert false
        elseif n < 0
            ssl_abandon(ctx)                                                    ;@🤖 "ssl_write 💥"
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
function f_send(c_bio, buf, nbytes)                                             ;@🤖 "f_send ➡️  $nbytes"
    bio = unsafe_pointer_to_objref(c_bio)
    if !isopen(bio) || bio.status == Base.StatusClosing
        return Cint(MBEDTLS_ERR_NET_CONN_RESET)
    end
    return Cint(unsafe_write(bio, buf, nbytes))
end


"""
Connect `f_send` and `f_recv` callback functions to `SSLContext`.
"""
function set_bio!(ctx::SSLContext, bio::T) where {T<:IO}
    isopen(bio) || throw(ArgumentError("`set_bio!` requires `isopen(bio)`"))
    ctx.bio = bio
    ssl_set_bio(ctx, pointer_from_objref(bio), c_send[], c_recv[])
    nothing
end


# Receiving Data

"""
While there are no decrypted bytes available but the connection is readable:
 - If the TLS buffer has no pending (unprocessed) data wait for
   more encrypted data to arrive on the underlying connection.
 - Run a zero-byte read to allow the library to process its internal buffer,
   and/or read from the underlying connection.
 - `ssl_unsafe_read` updates the `isreadable` and `bytesavailable` state.
"""
function wait_for_decrypted_data(ctx)
    lock(ctx.waitlock)
    try
        check_async_exception(ctx)
        while ctx.isreadable && ctx.bytesavailable <= 0
            if !ssl_check_pending(ctx)                                          ;@🤖 "wait_for_encrypted_data ⌛️";
                wait_for_encrypted_data(ctx)
            end
            ssl_unsafe_read(ctx, Ptr{UInt8}(C_NULL), UInt(0))                   ;@🤖 "wait_for_decrypted_data 📥  $(ctx.bytesavailable)"
        end
    finally
        unlock(ctx.waitlock)
    end
end


"""
    ssl_unsafe_read(::SSLContext, buf, nbytes)

Copies at most `nbytes` of decrypted data into `buf`.
Never blocks to wait for more data to arrive.
Returns number of bytes copied into `buf` (`<= nbytes`).
Updates `ctx.bytesavailable` with the number of decrypted bytes remaining in
the TLS buffer.

Stops when:
 - `nbytes` have been copied, or
 - there are no more decrypted bytes available in the TLS buffer, or
 - a TLS `close_notify` message is received.

When TLS `close_notify` is received:
 - `isreadable` is set to false and `bytesavailable` is set to zero.
   [RFC5246 7.2.1]: "Any data received after a closure alert is ignored."
 - the number of bytes read before the `close_notify` is returned as usual.

Throws a `MbedException` if `ssl_read` returns an unhandled error code.

When an unhandled exception occurs `isreadable` is set to false.
"""
function ssl_unsafe_read(ctx::SSLContext, buf::Ptr{UInt8}, nbytes::UInt)

    check_async_exception(ctx)

    ctx.isreadable ||
    throw(ArgumentError("`ssl_unsafe_read` requires `isreadable(::SSLContext)`"))

    nread::UInt = 0
    try
        while true

            n = ssl_read(ctx, buf + nread, nbytes - nread)                      ;@😬 "ssl_read ⬅️  $n $(n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ? "(CLOSE_NOTIFY)" :
                                                                                                        n == MBEDTLS_ERR_NET_CONN_RESET        ? "(CONN_RESET)" :
                                                                                                        n == MBEDTLS_ERR_SSL_WANT_READ         ? "(WANT_READ)" : "")"
            if n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ||
               n == MBEDTLS_ERR_NET_CONN_RESET
                ssl_abandon(ctx)
                return nread
            elseif n == MBEDTLS_ERR_SSL_WANT_READ
                ctx.bytesavailable = 0                                          ;@😬 "ssl_read ⌛️ $nread"
                return nread
            elseif n < 0
                ssl_abandon(ctx)
                throw(MbedException(n))
            end

            nread += n
            @assert nread <= nbytes

            if nread == nbytes
                ctx.bytesavailable = ssl_get_bytes_avail(ctx)                   ;@🤖 "ssl_read ⬅️  $nread, 📥  $(ctx.bytesavailable)"
                return nread
            end
        end
    catch e                                                                     ;@💀 "ssl_read 💥"
        ssl_abandon(ctx)
        rethrow(e)
    end

    @assert false "unreachable"
end


# Receiving Encrypted Data

function wait_for_encrypted_data(ctx)
    try
        eof(ctx.bio)
    catch e
        if !(e isa Base.IOError) || e.code != Base.UV_ECONNRESET
            rethrow(e)
        end
    end
end


"""
Copy at most `nbytes` of encrypted data to `buf` from the `bio` connection.
If no encrypted bytes are available return:
 - `MBEDTLS_ERR_SSL_WANT_READ` if the connection is still open, or
 - `MBEDTLS_ERR_NET_CONN_RESET` if it is closed.
"""
function f_recv(c_bio, buf, nbytes)
    @assert nbytes > 0
    bio = unsafe_pointer_to_objref(c_bio)
    n = bytesavailable(bio)
    if n == 0                                                                   ;@🤖 "f_recv $(isopen(bio) ? "WANT_READ" : "CONN_RESET")"
        return isopen(bio) ? Cint(MBEDTLS_ERR_SSL_WANT_READ) :
                             Cint(MBEDTLS_ERR_NET_CONN_RESET)
    end
    n = min(nbytes, n)                                                          ;@🤖 "f_recv ⬅️  $n"
    unsafe_read(bio, buf, n)
    return Cint(n)
end


# Base ::IO Write Methods -- wrappers for `ssl_unsafe_write`

Base.unsafe_write(ctx::SSLContext, msg::Ptr{UInt8}, N::UInt) =
    ssl_unsafe_write(ctx, msg, N)


Base.write(ctx::SSLContext, msg::UInt8) = write(ctx, Ref(msg))


# Base ::IO Read Methods -- wrappers for `ssl_unsafe_read`

"""
Copy `nbytes` of decrypted data from `ctx` into `buf`.
Wait for sufficient decrypted data to be available.
Throw `EOFError` if the peer sends TLS `close_notify` or closes the
connection before `nbytes` have been copied.
"""
function Base.unsafe_read(ctx::SSLContext, buf::Ptr{UInt8}, nbytes::UInt)
    nread = 0
    while nread < nbytes
        if eof(ctx)                                                             ;@💀 "unsafe_read 🛑"
            throw(EOFError())
        end
        nread += ssl_unsafe_read(ctx, buf + nread, nbytes - nread)
    end                                                                         ;@😬 "unsafe_read ⬅️ $nread"
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
        if (nread == nbytes) || !all || eof(ctx)
            break
        end
    end                                                                         ;@😬 "readbytes! ⬅️  $nread"
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
    buf = Vector{UInt8}(undef, n)
    n = ssl_unsafe_read(ctx, pointer(buf), n)                                   ;@😬 "readavailable ⬅️  $n"
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

# follows steps described here:
# https://tls.mbed.org/discussions/crypto-and-ssl/client-ca-load-where-can-i-get-the-right-crt-if-i-access-a-web-site
const _crypt32 = "Crypt32.dll"
const _ole32 = "Ole32.dll"
HANDLE = Ptr{Cvoid}
HCRYPTPROV = HANDLE
HCRYPTPROV_LEGACY = HCRYPTPROV
HCERTSTORE = HANDLE
LPWSTR = Cwstring #Ptr{Cushort} # Cwstring, Ptr{UInt16}
LPCWSTR = Cwstring #Ptr{Cushort} # Cwstring, Ptr{UInt16}
LPCOLESTR = Cwstring
LPSTR = Cstring #Ptr{UInt8} # Cstring?
BOOL = Cint
BYTE = Cuchar #Cint #UInt8 # Cint
DWORD = Culong

# https://docs.microsoft.com/en-us/windows/win32/com/com-error-codes-4
const CRYPT_E_NOT_FOUND = 0x80092004
const X509_ASN_ENCODING = 0x00000001
const CERT_NAME_FRIENDLY_DISPLAY_TYPE = 5
const CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
const CERT_NAME_ISSUER_FLAG = 0x1

const COINIT_APARTMENTTHREADED = 0x2
const CLSCTX_INPROC_SERVER = 0x1

struct CRYPT_INTEGER_BLOB
    cbData::DWORD     # DWORD cbData
    pbData::Ptr{BYTE} # BYTE  *pbData
end
CRYPT_OBJID_BLOB = CRYPT_INTEGER_BLOB
CERT_NAME_BLOB = CRYPT_INTEGER_BLOB

struct CRYPT_ALGORITHM_IDENTIFIER
    pszObjId::LPSTR              # LPSTR            pszObjId
    Parameters::CRYPT_OBJID_BLOB # CRYPT_OBJID_BLOB Parameters
end

struct FILETIME
  dwLowDateTime::DWORD  # DWORD dwLowDateTime
  dwHighDateTime::DWORD # DWORD dwHighDateTime
end

struct CRYPT_BIT_BLOB
  cbData::DWORD      # DWORD cbData
  pbData::Ptr{BYTE}  # BYTE  *pbData
  cUnusedBits::DWORD # DWORD cUnusedBits
end

struct CERT_PUBLIC_KEY_INFO
    Algorithm::CRYPT_ALGORITHM_IDENTIFIER # CRYPT_ALGORITHM_IDENTIFIER Algorithm
    PublicKey::CRYPT_BIT_BLOB             # CRYPT_BIT_BLOB             PublicKey
end

struct CERT_EXTENSION
  pszObjId::LPSTR         # LPSTR            pszObjId
  fCritical::BOOL         # BOOL             fCritical
  Value::CRYPT_OBJID_BLOB # CRYPT_OBJID_BLOB Value
end

struct CERT_INFO
    dwVersion::DWORD                               # DWORD                      dwVersion
    SerialNumber::CRYPT_INTEGER_BLOB               # CRYPT_INTEGER_BLOB         SerialNumber
    SignatureAlgorithm::CRYPT_ALGORITHM_IDENTIFIER # CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm
    Issuer::CERT_NAME_BLOB                         # CERT_NAME_BLOB             Issuer
    NotBefore::FILETIME                            # FILETIME                   NotBefore
    NotAfter::FILETIME                             # FILETIME                   NotAfter
    Subject::CERT_NAME_BLOB                        # CERT_NAME_BLOB             Subject
    SubjectPublicKeyInfo::CERT_PUBLIC_KEY_INFO     # CERT_PUBLIC_KEY_INFO       SubjectPublicKeyInfo
    IssuerUniqueId::CRYPT_BIT_BLOB                 # CRYPT_BIT_BLOB             IssuerUniqueId
    SubjectUniqueId::CRYPT_BIT_BLOB                # CRYPT_BIT_BLOB             SubjectUniqueId
    cExtension::DWORD                              # DWORD                      cExtension
    rgExtension::Ptr{CERT_EXTENSION}               # PCERT_EXTENSION            rgExtension
end
PCERT_INFO = Ptr{CERT_INFO}

struct CERT_CONTEXT
    dwCertEncodingType::DWORD #   DWORD      dwCertEncodingType; # e.g. X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
    pbCertEncoded::Ptr{BYTE}  #   BYTE       *pbCertEncoded;     # A pointer to a buffer that contains the encoded certificate.
    cbCertEncoded::DWORD      #   DWORD      cbCertEncoded;      # The size, in bytes, of the encoded certificate.
    pCertInfo::PCERT_INFO     # PCERT_INFO pCertInfo
    hCertStore::HCERTSTORE    # HCERTSTORE hCertStore
end
PCCERT_CONTEXT = Ptr{CERT_CONTEXT}

struct _GUID
    Data::UInt128
    # unsigned long Data1;
    # unsigned short Data2;
    # unsigned short Data3;
    # Data4:: # unsigned char Data4[8];
end

LPCLSID = Ptr{UInt128} # Ptr{_GUID}
BSTR = Cwstring # technically a pointer to the first character of the string
HRESULT = Int32
LPVOID = Ptr{Cvoid}
REFCLSID = Array{UInt8,1} # UInt128 # _GUID
LPUNKNOWN = HANDLE
REFIID = Array{UInt8,1} # UInt128 # _GUID

function load_system_crl!(config::SSLConfig) end

if Sys.iswindows()
    # Access COM Objects without registering
    function MyCoCreateInstance(dllname, rclsid::REFCLSID, pUnkOuter::LPUNKNOWN, riid::REFIID, ppv) #::Ptr{LPVOID})
        hr = 0x80040152; #REGDB_E_KEYMISSING;

        # HMODULE hDll = ::LoadLibrary(szDllName);
        # if (hDll == 0)
        #   return hr;

        # typedef HRESULT (__stdcall *pDllGetClassObject)(IN REFCLSID rclsid,
        #                  IN REFIID riid, OUT LPVOID FAR* ppv);
        #
        # pDllGetClassObject GetClassObject =
        #    (pDllGetClassObject)::GetProcAddress(hDll, "DllGetClassObject");
        # if (GetClassObject == 0)
        # {
        #   ::FreeLibrary(hDll);
        #   return hr;
        # }

        IID_IClassFactory =  Vector{UInt8}(undef, 16) # convert(UInt128, 0)

        # FIXME: didn't like non-const dllname, hardcoding to _ole32
        hr = ccall((:CLSIDFromString, _ole32), HRESULT, (LPCOLESTR, LPCLSID),
            "{00000001-0000-0000-C000-000000000046}", pointer(IID_IClassFactory)) # Unknwn.h
        @show IID_IClassFactory

        # IClassFactory *pIFactory;
        pIFactory = Ref(Ptr{Cvoid}(0))

        # hr = GetClassObject(rclsid, IID_IClassFactory, (LPVOID *)&pIFactory);
        ccall((:DllGetClassObject, _ole32), HRESULT, (REFCLSID, REFIID, Ptr{LPVOID}),
            rclsid, IID_IClassFactory, pIFactory)
        println("$(@__LINE__)")
        @show pIFactory[]
        println("$(@__LINE__)")
        hr < 0 && error("Failed DllGetClassObject pIFactory: HRESULT 0x$(string(UInt32(hr), base=16))")
        println("$(@__LINE__)")
        # 5 functions:
        # QueryInterface, AddRef, Release, CreateInstance, LockServer
        IFactory = unsafe_wrap(Vector{Ptr{Cvoid}}, pIFactory[], (5, ) )
        println("$(@__LINE__)")

        ppv = Ref(Ptr{Cvoid}(0))
        println("$(@__LINE__)")
        # hr = pIFactory->CreateInstance(pUnkOuter, riid, ppv);
        hr = ccall(IFactory[4], HRESULT, (LPUNKNOWN, REFIID, LPVOID), pUnkOuter, riid, ppv)
        println("$(@__LINE__)")
        hr < 0 && error("Failed IFactory::CreateInstance ppv: HRESULT 0x$(string(UInt32(hr), base=16))")
        println("$(@__LINE__)")

        # pIFactory->Release();
        hr = ccall(IFactory[3], HRESULT, ())
        println("$(@__LINE__)")
        hr < 0 && error("Failed IFactory::Release, HRESULT 0x$(string(UInt32(hr), base=16))")
        println("$(@__LINE__)")

        return (hr, ppv);
    end

    # https://docs.microsoft.com/en-us/windows/win32/api/certadm/nf-certadm-icertadmin-getcrl
    function load_system_crl!(config::SSLConfig)
        # ICertAdmin * pCertAdmin = NULL;  // pointer to interface object
        # BSTR bstrCA = NULL;              // variable for machine\CAName
        # BSTR bstrCRL = NULL;             // variable to contain
        #                                  // the retrieved CRL
        #
        # HRESULT hr;
        #
        # //  Initialize COM.
        # hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        hr = ccall((:CoInitializeEx, _ole32), HRESULT, (LPVOID, DWORD),
                    C_NULL, COINIT_APARTMENTTHREADED)
        hr < 0 && error("Failed CoInitializeEx: HRESULT 0x$(string(UInt32(hr), base=16))")
        # if (FAILED(hr))
        # {
        #     printf("Failed CoInitializeEx [%x]\n", hr);
        #     goto error;
        # }
        #
        # //  Create the CertAdmin object
        # //  and get a pointer to its ICertAdmin interface.
        # hr = CoCreateInstance( CLSID_CCertAdmin,
        #                        NULL,
        #                        CLSCTX_INPROC_SERVER,
        #                        IID_ICertAdmin,
        #                        (void **)&pCertAdmin);
        # CLSID_CCertAdmin = UUID("37eabaf0-7fb6-11d0-8817-00a0c903b83c").value # CertAdm.h
        CLSID_CCertAdmin =  Vector{UInt8}(undef, 16) # convert(UInt128, 0)

        hr = ccall((:CLSIDFromString, _ole32), HRESULT, (LPCOLESTR, LPCLSID),
            "{37eabaf0-7fb6-11d0-8817-00a0c903b83c}", pointer(CLSID_CCertAdmin))
        @show CLSID_CCertAdmin
        # IID_ICertAdmin = UUID("34df6950-7fb6-11d0-8817-00a0c903b83c").value # CertAdm.h
        # @show string(IID_ICertAdmin, base=16)

        IID_ICertAdmin =  Vector{UInt8}(undef, 16)
        hr = ccall((:CLSIDFromString, _ole32), HRESULT, (LPCOLESTR, LPCLSID),
            "{34df6950-7fb6-11d0-8817-00a0c903b83c}", pointer(IID_ICertAdmin))
        @show IID_ICertAdmin

        pCertAdmin = Ref(Ptr{Cvoid}(0)) #Vector{UInt8}(undef, 16)

        if false
            hr = ccall((:CoCreateInstance, _ole32), HRESULT,
                        (REFCLSID,        LPUNKNOWN, DWORD,                REFIID,         LPVOID),
                        CLSID_CCertAdmin, C_NULL,    CLSCTX_INPROC_SERVER, IID_ICertAdmin, pCertAdmin ) # TODO: make sure pCertAdmin is populating
        else
            hr = MyCoCreateInstance(_ole32, CLSID_CCertAdmin, C_NULL, IID_ICertAdmin, pCertAdmin)
        end
        @show pCertAdmin
        hr < 0 && error("Failed CoCreateInstance pCertAdmin: HRESULT 0x$(string(UInt32(hr), base=16))")

        # access the 10 functions insided of the COM interface
        certAdm = unsafe_wrap(Vector{Ptr{Cvoid}}, pCertAdmin[], (10, ) )

        # if (FAILED(hr))
        # {
        #     printf("Failed CoCreateInstance pCertAdmin [%x]\n", hr);
        #     goto error;
        # }
        #
        # //  Note the use of two backslashes (\\)
        # //  in C++ to produce one backslash (\).
        # bstrCA = SysAllocString(L"<COMPUTERNAMEHERE>\\<CANAMEHERE>");
        # if (FAILED(hr))
        # {
        #     printf("Failed to allocate memory for bstrCA\n");
        #     goto error;
        # }
        #
        # //  Retrieve the CRL.
        # hr = pCertAdmin->GetCRL( bstrCA, CR_OUT_BINARY, &bstrCRL );
        # if (FAILED(hr))
        # {
        #     printf("Failed GetCRL [%x]\n", hr);
        #     goto error;
        # }
        # else
        #     printf("CRL retrieved successfully\n");
        #     //  Use the CRL as needed.
        #
        # //  Done processing.
        #
        # error:
        #
        # //  Free BSTR values.
        # if (NULL != bstrCA)
        #     SysFreeString(bstrCA);
        #
        # if (NULL != bstrCRL)
        #     SysFreeString(bstrCRL);
        #
        # //  Clean up object resources.
        # if (NULL != pCertAdmin)
        #     pCertAdmin->Release();
        #
        # //  Free COM resources.
        # CoUninitialize();
    end
end

"""

    ca_chain_with_root_store!(config::SSLConfig; stores=["ROOT", "AuthRoot", "CA"], debug_output=false)

Populate the certificate authority chain with root certificates from the systems root certificate `stores`.

Currently only implemented on Windows.  If `debug_output` is enabled, look at stdout and compare to the certificates found in `certmgr.msc`.

# Example
```
conf = MbedTLS.SSLConfig()
MbedTLS.ca_chain_with_root_store!(conf; debug_output=true)
```
"""
function ca_chain_with_root_store!(config::SSLConfig; stores=["ROOT", "AuthRoot", "CA"], debug_output=false) end

if Sys.iswindows()
    function ca_chain_with_root_store!(config::SSLConfig; stores=["ROOT", "AuthRoot", "CA"], debug_output=false)
        # chain = crt_parse_file(joinpath(dirname(@__FILE__), "../deps/cacert.pem"))
        config.chain = CRT()

        # 1. Initialize an mbedTLS certificate using mbedtls_x509_crt_init(my_ca_chain).
        ## default CRT object stored in chain is initialized with mbedtls_x509_crt_init already

        # 2. Call CertOpenSystemStore, passing ROOT as the system store name.
        ## https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopensystemstorew

        for store in stores
            if debug_output
                @show store
            end
            hcertstore = ccall((:CertOpenSystemStoreW, _crypt32), HCERTSTORE, (HCRYPTPROV_LEGACY, LPCWSTR),
                C_NULL, store)

            hcertstore == C_NULL && error("CertOpenSystemStore failed: \"$(Libc.FormatMessage())\"")

            # 3. Repeatedly call CertEnumCertificatesInStore until CRYPT_E_NOT_FOUND.
            pccert_context = ccall((:CertEnumCertificatesInStore, _crypt32), PCCERT_CONTEXT, (HCERTSTORE, PCCERT_CONTEXT),
                hcertstore, C_NULL)

            pccert_context == C_NULL && error("CertEnumCertificatesInStore returned null on init: \"$(Libc.FormatMessage())\"")
            count = 0
            last_error = 0
            while last_error != CRYPT_E_NOT_FOUND && pccert_context != C_NULL
                # println("Cert Count = $(count)")
                # 4. For each cert in the store, I check that it has X509_ASN_ENCODING.
                store_cert = unsafe_load(pccert_context)
                store_cert_info = unsafe_load(store_cert.pCertInfo)
                issuer = unsafe_string(store_cert_info.Issuer.pbData, store_cert_info.Issuer.cbData)
                subject = unsafe_string(store_cert_info.Subject.pbData, store_cert_info.Subject.cbData)
                if (store_cert.dwCertEncodingType & X509_ASN_ENCODING) != 0

                    if debug_output
                        buf_size = 1024
                        buffer = Vector{UInt8}(undef, buf_size)
                        # name = ccall((:CertGetNameStringW, _crypt32), DWORD,
                        #     (PCCERT_CONTEXT, DWORD, DWORD, Cvoid, LPSTR, DWORD),
                        #     pccert_context, CERT_NAME_FRIENDLY_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG)
                        retval = ccall((:CertNameToStrA, _crypt32), DWORD,
                            (DWORD, CERT_NAME_BLOB, DWORD, Ptr{UInt8}, DWORD),
                            X509_ASN_ENCODING, store_cert_info.Issuer, 2, buffer, buf_size)
                        issuer = String(buffer[1:retval - 1])
                        println(issuer)
                    end

                    # 5. If so I call mbedtls_x509_crt_parse(my_ca_chain, store_cert->pbCertEncoded, store_cert->cbCertEncoded)
                    # to load the certificate from the store into my certificate chain.
                    ## similar to crt_parse!(chain, buf::String), but the data isn't in a String
                    ret = ccall((:mbedtls_x509_crt_parse, libmbedx509), Cint,
                        (Ptr{Cvoid}, Ptr{UInt8}, Csize_t),
                        config.chain.data, store_cert.pbCertEncoded, store_cert.cbCertEncoded)
                    #ret == 0 || mbed_err(ret)
                end

                pccert_context = ccall((:CertEnumCertificatesInStore, _crypt32), PCCERT_CONTEXT, (HCERTSTORE, PCCERT_CONTEXT),
                    hcertstore, pccert_context)

                last_error = Libc.GetLastError()
                count += 1
            end
            if debug_output
                @show count
            end

            @assert last_error == CRYPT_E_NOT_FOUND

            # Cleanup handle to CertStore
            retval = ccall((:CertCloseStore, _crypt32), BOOL, (HCERTSTORE, DWORD),
                hcertstore, 0)

            retval == 0 && error("CertCloseStore failed: \"$(Libc.FormatMessage())\"")
        end

        # I then use my_ca_chain with mbedtls_ssl_conf_ca_chain(...) when setting up the ssl config.
        ccall((:mbedtls_ssl_conf_ca_chain, libmbedtls), Cvoid,
            (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
            config.data, config.chain.data, C_NULL)
    end
end

"""
Enable / Disable renegotiation support for connection when initiated by peer
(MBEDTLS_SSL_RENEGOTIATION_ENABLED or MBEDTLS_SSL_RENEGOTIATION_DISABLED).
See: https://tls.mbed.org/api/ssl_8h.html#aad4f50fc1c0a018fd5eb18fd9621d0d3
"""
function ssl_conf_renegotiation!(config::SSLConfig, renegotiation)
    ccall((:mbedtls_ssl_conf_renegotiation, libmbedtls), Cvoid,
        (Ptr{Cvoid}, Cint),
        config.data, renegotiation)
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

function ssl_set_bio(ctx::SSLContext, bio, f_send::Ptr{Cvoid}, f_recv::Ptr{Cvoid})
    @lockdata ctx begin
        ccall((:mbedtls_ssl_set_bio, libmbedtls), Cvoid,
            (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
            ctx.data, bio, f_send, f_recv, C_NULL)
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

"""
Reset an already initialized SSL context for re-use while retaining
application-set variables, function pointers and data.
"""
function ssl_session_reset(ctx::SSLContext)
    @lockdata ctx begin
        return ccall((:mbedtls_ssl_session_reset, libmbedtls),
                     Cint, (Ptr{Cvoid},), ctx.data)
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
