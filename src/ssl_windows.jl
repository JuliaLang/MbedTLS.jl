
# follows steps described here:
# https://tls.mbed.org/discussions/crypto-and-ssl/client-ca-load-where-can-i-get-the-right-crt-if-i-access-a-web-site
const _crypt32 = "Crypt32.dll"
const _ole32 = "Ole32.dll"
const _kernel32 = "Kernel32.dll"
HANDLE = Ptr{Cvoid}
HCRYPTPROV = HANDLE
HCRYPTPROV_LEGACY = HCRYPTPROV
HCERTSTORE = HANDLE
LPWSTR = Cwstring #Ptr{Cushort} # Cwstring, Ptr{UInt16}
LPCWSTR = Cwstring #Ptr{Cushort} # Cwstring, Ptr{UInt16}
LPCOLESTR = Cwstring
LPSTR = Cstring #Ptr{UInt8} # Cstring?
LPCSTR = Cstring #Ptr{UInt8} # Cstring?
BOOL = Cint
BYTE = Cuchar #Cint #UInt8 # Cint
DWORD = Culong
LONG = Int32

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

# struct FILETIME
#   dwLowDateTime::DWORD  # DWORD dwLowDateTime
#   dwHighDateTime::DWORD # DWORD dwHighDateTime
# end
FILETIME = Int64 # works better with Filetimes.jl

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

struct CRL_ENTRY
SerialNumber::CRYPT_INTEGER_BLOB  # CRYPT_INTEGER_BLOB SerialNumber;
RevocationDate::FILETIME          # FILETIME           RevocationDate;
cExtension::DWORD                 # DWORD              cExtension;
rgExtension::Ptr{CERT_EXTENSION}  # PCERT_EXTENSION    rgExtension;
end
PCRL_ENTRY = Ptr{CRL_ENTRY}

struct CRL_INFO
    dwVersion::DWORD                               # DWORD                      dwVersion;
    SignatureAlgorithm::CRYPT_ALGORITHM_IDENTIFIER # CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
    Issuer::CERT_NAME_BLOB                         # CERT_NAME_BLOB             Issuer;
    ThisUpdate::FILETIME                           # FILETIME                   ThisUpdate;
    NextUpdate::FILETIME                           # FILETIME                   NextUpdate;
    cCRLEntry::DWORD                               # DWORD                      cCRLEntry;
    rgCRLEntry::PCRL_ENTRY                         # PCRL_ENTRY                 rgCRLEntry;
    cExtension::DWORD                              # DWORD                      cExtension;
    rgExtension::Ptr{CERT_EXTENSION}               # PCERT_EXTENSION            rgExtension;
end
PCRL_INFO = Ptr{CRL_INFO}

struct CRL_CONTEXT
    dwCertEncodingType::DWORD #   DWORD      dwCertEncodingType; # e.g. X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
    pbCrlEncoded::Ptr{BYTE}  #   BYTE       *pbCertEncoded;     # A pointer to a buffer that contains the encoded certificate.
    cbCrlEncoded::DWORD      #   DWORD      cbCertEncoded;      # The size, in bytes, of the encoded certificate.
    pCrlInfo::PCRL_INFO     # PCERT_INFO pCertInfo
    hCertStore::HCERTSTORE    # HCERTSTORE hCertStore
end
PCCRL_CONTEXT = Ptr{CRL_CONTEXT}

struct _GUID
    Data::UInt128
    # unsigned long Data1;
    # unsigned short Data2;
    # unsigned short Data3;
    # Data4:: # unsigned char Data4[8];
end

LPCLSID =  Ptr{UInt128} # Ptr{_GUID}
BSTR = Cwstring # technically a pointer to the first character of the string
HRESULT = Int32
LPVOID = Ptr{Cvoid}
REFCLSID = Ptr{UInt128} #Array{UInt8,1} #  Ptr{UInt128}????   # UInt128 # _GUID
LPUNKNOWN = HANDLE
REFIID = Ptr{UInt128} #Array{UInt8,1} # UInt128 # _GUID

mutable struct IClassFactory
    QueryInterface::Ptr
    AddRef::Ptr
    Release::Ptr
    CreateInstance::Ptr
    LockServer::Ptr
end

# S_OK             Operation successful                   0x00000000
# E_ABORT          Operation aborted                      0x80004004
# E_ACCESSDENIED   General access denied error            0x80070005
# E_FAIL           Unspecified failure                    0x80004005
# E_HANDLE         Handle that is not valid               0x80070006
# E_INVALIDARG     One or more arguments are not valid    0x80070057
# E_NOINTERFACE    No such interface supported            0x80004002
# E_NOTIMPL        Not implemented                        0x80004001
# E_OUTOFMEMORY    Failed to allocate necessary memory    0x8007000E
# E_POINTER        Pointer that is not valid              0x80004003
# E_UNEXPECTED     Unexpected failure                     0x8000FFFF

# "Class not registered (Exception from HRESULT: 0x80040154 (REGDB_E_CLASSNOTREG))"


function ca_chain_with_root_store!(config::SSLConfig; stores=["CA", "AuthRoot", "Root", "TrustedPublisher"], debug_output=false)
    # chain = crt_parse_file(joinpath(dirname(@__FILE__), "../deps/cacert.pem"))
    config.chain = CRT()
    config.crl_chain = CRL()

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
        last_error = Libc.GetLastError() & 0x7fffffff
        pccert_context == C_NULL && (println(stderr, "Skipping certificate store \"$(store)\": CertEnumCertificatesInStore returned null on init: 0x$(string(reinterpret(UInt32, last_error),base=16)) \"$(Libc.FormatMessage(last_error))\""); continue)
        count = 0
        last_error = 0 # Libc.GetLastError()
        while last_error != CRYPT_E_NOT_FOUND && pccert_context != C_NULL
            # println("Cert Count = $(count)")
            # 4. For each cert in the store, I check that it has X509_ASN_ENCODING.
            store_cert = unsafe_load(pccert_context)
            store_cert_info = unsafe_load(store_cert.pCertInfo)
            issuer = unsafe_string(store_cert_info.Issuer.pbData, store_cert_info.Issuer.cbData)
            subject = unsafe_string(store_cert_info.Subject.pbData, store_cert_info.Subject.cbData)
            if (store_cert.dwCertEncodingType & X509_ASN_ENCODING) != 0


                if debug_output
                    buf_size = Int32(2048)
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

                if debug_output
                    oid_to_str = Dict{String, String}(
                        "1.3.6.1.4.1.311.2.1.27" => "SPC_FINANCIAL_CRITERIA_OBJID",
                        "1.3.6.1.4.1.311.2.1.10" => "SPC_SP_AGENCY_INFO_OBJID",
                        "1.3.6.1.5.5.7.1.1" => "szOID_AUTHORITY_INFO_ACCESS",
                        "2.5.29.35" => "szOID_AUTHORITY_KEY_IDENTIFIER2",
                        "2.5.29.19" => "szOID_BASIC_CONSTRAINTS2",
                        "2.5.29.32" => "szOID_CERT_POLICIES",
                        "2.5.29.31" => "szOID_CRL_DIST_POINTS",
                        "2.5.29.21" => "szOID_CRL_REASON_CODE",
                        "2.5.29.37" => "szOID_ENHANCED_KEY_USAGE",
                        "2.5.29.18" => "szOID_ISSUER_ALT_NAME2",
                        "2.5.29.2" => "szOID_KEY_ATTRIBUTES",
                        "2.5.29.15" => "szOID_KEY_USAGE",
                        "2.5.29.4" => "szOID_KEY_USAGE_RESTRICTION",
                        "1.3.6.1.4.1.311.10.2" => "szOID_NEXT_UPDATE_LOCATION",
                        "1.2.840.113549.1.9.15" => "szOID_RSA_SMIMECapabilities",
                        "2.5.29.17" => "szOID_SUBJECT_ALT_NAME2",
                        "2.5.29.14" => "szOID_SUBJECT_KEY_IDENTIFIER",
                        "1.2.840.113533.7.65.0" => "entrust version",
                        "1.3.6.1.4.1.311.20.2" => "szOID_ENROLL_CERTTYPE_EXTENSION",
                        "1.3.6.1.4.1.311.21.1" => "szOID_CERTSRV_CA_VERSION",
                        "1.3.6.1.4.1.311.21.2" => "szOID_CERTSRV_PREVIOUS_CERT_HASH",
                        "1.3.6.1.5.5.7.1.12" => "id-pe-logotype",
                        "2.16.840.1.113730.1.1" => "SSL client, an SSL server, or a CA",
                        "2.16.840.1.113730.1.13" => "free-form text comments",
                        "2.5.29.1" => "CA serial number",
                        "2.5.29.10" => "basicConstraints",
                        "2.5.29.16" => "Private key usage period",
                    )
                    # Print the extra info key value pairs
                    buf_size = Int32(2048)
                    buffer = Vector{UInt8}(undef, buf_size)
                    buf_size_in_out = Vector{Int32}(undef, 1)
                    for i in 1:store_cert_info.cExtension
                        # buf_size gets rewritten by CryptFormatObject, so reset it for each pass thru
                        buf_size = Int32(2048)

                        # @show i

                        cert_extension = unsafe_load(store_cert_info.rgExtension, i)

                        # BOOL CryptFormatObject(
                        #   DWORD      dwCertEncodingType,
                        #   DWORD      dwFormatType, # always zero
                        #   DWORD      dwFormatStrType, # 0 is single line, 0x0001 multiline, 0x0010 no hex
                        #   void       *pFormatStruct, # always NULL
                        #   LPCSTR     lpszStructType, # OID, aka cert_extension.pszObjId
                        #   const BYTE *pbEncoded, # BLOB.pbData
                        #   DWORD      cbEncoded,  # BLOB.cbData
                        #   void       *pbFormat, # pointer to buffer
                        #   DWORD      *pcbFormat # pointer to number of bytes in buffer, retrieves number of bytes set
                        # );
                        buf_size_in_out[1] = buf_size

                        retval = ccall((:CryptFormatObject, _crypt32), BOOL,
                            (DWORD, DWORD, DWORD, Ptr{Cvoid}, LPCSTR,
                            Ptr{BYTE}, DWORD,
                            Ptr{Cvoid}, Ptr{DWORD}), #Base.RefValue{Int64}),
                            store_cert.dwCertEncodingType, 0, 0, C_NULL, cert_extension.pszObjId,
                            cert_extension.Value.pbData, cert_extension.Value.cbData,
                            buffer, buf_size_in_out)
                        last_error = Libc.GetLastError()

                        if retval != 0
                            # @show buf_size_in_out

                            # cert_extension_val = String(buffer[1:buf_size_in_out[1] - 1])
                            cert_extension_val = transcode(String, reinterpret(UInt16, buffer[1:buf_size_in_out[1]])[1:end - 1])
                            oid = unsafe_string(cert_extension.pszObjId)
                            println("  Extension $(i). $(get(oid_to_str, oid, "?? $(oid)")): $(cert_extension_val)")
                        else
                            try
                                println("Error retrieving extension: \"$(Libc.FormatMessage(last_error))\"")
                                @show buf_size_in_out
                            catch
                                println("error looking at the error???")
                            end
                            #buf_size = Int32(buf_size_in_out[1])
                            #buffer = Vector{UInt8}(undef, buf_size)
                        end
                    end
                end

                if debug_output

                    prop_id_to_str = Dict{Any,Any}(
                        0x00000003 => "CERT_SHA1_HASH_PROP_ID", # 3
                        0x00000004 => "CERT_MD5_HASH_PROP_ID", # 4
                        0x00000009 => "CERT_ENHKEY_USAGE_PROP_ID", # 9
                        0x0000000b => "CERT_FRIENDLY_NAME_PROP_ID", # 11, string
                        0x0000000f => "CERT_SIGNATURE_HASH_PROP_ID", # 15
                        0x00000014 => "CERT_KEY_IDENTIFIER_PROP_ID", # 20
                        0x00000018 => "CERT_ISSUER_PUBLIC_KEY_MD5_HASH_PROP_ID", # 24
                        0x00000019 => "CERT_SUBJECT_PUBLIC_KEY_MD5_HASH_PROP_ID", # 25
                        0x0000001d => "CERT_SUBJECT_NAME_MD5_HASH_PROP_ID", # 29, CERT_EXTENDED_ERROR_INFO_PROP_ID ?
                        0x0000004b => "CERT_OCSP_CACHE_PREFIX_PROP_ID", # 75, string
                        0x00000053 => "CERT_ROOT_PROGRAM_CERT_POLICIES_PROP_ID", # 83
                        0x00000059 => "CERT_SIGN_HASH_CNG_ALG_PROP_ID", # 89, string
                        0x0000005c => "CERT_SUBJECT_PUB_KEY_BIT_LENGTH_PROP_ID", # 92
                        0x00000062 => "CERT_AUTH_ROOT_SHA256_HASH_PROP_ID", # 98
                        0x00000068 => "CERT_DISALLOWED_FILETIME_PROP_ID", # 104
                        0x00000069 => "CERT_ROOT_PROGRAM_CHAIN_POLICIES_PROP_ID", # 105
                        0x0000006b => "CERT_SHA256_HASH_PROP_ID", # 107
                        0x0000007a => "CERT_DISALLOWED_ENHKEY_USAGE_PROP_ID", # 122
                        0x0000007c => "CERT_PIN_SHA256_HASH_PROP_ID", # 124
                        0x0000007e => "CERT_NOT_BEFORE_FILETIME_PROP_ID", # 126
                        0x0000007f => "CERT_NOT_BEFORE_ENHKEY_USAGE_PROP_ID"  # 127
                    )
                    string_props = [0x0000000b, 0x0000004b, 0x00000059]

                    # get certificate context properties, especially CERT_EXTENDED_ERROR_INFO_PROP_ID
                    filetime_size = Int32(8)
                    filetime_buffer = Vector{UInt8}(undef, filetime_size)
                    filetime_size_in_out = Vector{Int32}(undef, 1)

                    # DWORD CertEnumCertificateContextProperties(
                    #   PCCERT_CONTEXT pCertContext,
                    #   DWORD          dwPropId
                    # );
                    CERT_DISALLOWED_FILETIME_PROP_ID = 104
                    filetime_size_in_out[1] = filetime_size
                    dwPropId = CERT_DISALLOWED_FILETIME_PROP_ID
                    retval = ccall((:CertGetCertificateContextProperty, _crypt32), BOOL, (PCCERT_CONTEXT, DWORD, Ptr{Cvoid}, Ptr{DWORD}),
                                    pccert_context, dwPropId, filetime_buffer, filetime_size_in_out)
                    if retval != 0
                        @show "NotBefore:", Filetimes.datetime(store_cert_info.NotBefore)
                        @show "NotAfter:", Filetimes.datetime(store_cert_info.NotAfter)
                        @show "Disallowed:", Filetimes.datetime(reinterpret(Int64, filetime_buffer[1:filetime_size_in_out[1]])[1])
                        # @show Filetimes.datetime(store_cert_info.NotBefore)
                        if false
                            retval = ccall((:CompareFileTime, _kernel32), LONG, (Ptr{FILETIME}, Ptr{FILETIME}), filetime_buffer, Ref(store_cert_info.NotBefore))
                            # Disallowed > Not before: 1,  First file time is later than second file time.
                            # Disallowed < Not after: -1,  First file time is later than second file time.
                            println("CompareFileTime $(retval) : \"$(Libc.FormatMessage(last_error))\"")
                        end
                    end

                    buf_size = Int32(2048)
                    buffer = Vector{UInt8}(undef, buf_size)
                    buf_size_in_out = Vector{Int32}(undef, 1)
                    dwPropId = 0
                    i = 1
                    while((dwPropId = ccall((:CertEnumCertificateContextProperties, _crypt32), DWORD, (Ptr{CERT_CONTEXT}, DWORD),
                                                                                                        pccert_context, dwPropId)) > 0)
                        # BOOL CertGetCertificateContextProperty(
                        #   PCCERT_CONTEXT pCertContext,
                        #   DWORD          dwPropId,
                        #   void           *pvData,
                        #   DWORD          *pcbData
                        # );
                        # https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetcertificatecontextproperty
                        buf_size_in_out[1] = buf_size
                        retval = ccall((:CertGetCertificateContextProperty, _crypt32), BOOL, (PCCERT_CONTEXT, DWORD, Ptr{Cvoid}, Ptr{DWORD}),
                                        pccert_context, dwPropId, buffer, buf_size_in_out)
                        # retval = ccall((:CertGetCertificateContextProperty, _crypt32), BOOL, (PCCERT_CONTEXT, DWORD, Ptr{Cvoid}, Ptr{DWORD}),
                        #                 pccert_context, dwPropId, buffer, buf_size_in_out)
                        last_error = Libc.GetLastError()


                        if retval != 0
                            cert_property_data = transcode(String, reinterpret(UInt16, buffer[1:buf_size_in_out[1] + mod(buf_size_in_out[1], 2)])[1:end - 1])
                            println("  Prop $(i). $(get(prop_id_to_str, dwPropId, "?? $(dwPropId)")): $((dwPropId in string_props) ? cert_property_data : "bytes[$(buf_size_in_out[1])]")")
                        else
                            try
                                println("Error retrieving property: $(get(prop_id_to_str, dwPropId, "??")) \"$(Libc.FormatMessage(last_error))\"")
                                @show buf_size_in_out
                            catch
                                println("error looking at the error???")
                            end
                        end
                        i += 1
                    end
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

        if debug_output
            println("Getting CRLs in Store")
        end
        # Done getting certificates.  Now load all the CRLs in the store and push them to MbedTLS
        pccrl_context = ccall((:CertEnumCRLsInStore, _crypt32), PCCRL_CONTEXT, (HCERTSTORE, PCCRL_CONTEXT),
            hcertstore, C_NULL)
        count = 0
        last_error = 0 # Libc.GetLastError()
        while last_error != CRYPT_E_NOT_FOUND && pccrl_context != C_NULL
            store_crl = unsafe_load(pccrl_context)
            store_crl_info = unsafe_load(store_crl.pCrlInfo)
            # @show store_crl
            if (store_crl.dwCertEncodingType & X509_ASN_ENCODING) != 0

                if debug_output
                    buf_size = 1024
                    buffer = Vector{UInt8}(undef, buf_size)
                    retval = ccall((:CertNameToStrA, _crypt32), DWORD,
                        (DWORD, CERT_NAME_BLOB, DWORD, Ptr{UInt8}, DWORD),
                        X509_ASN_ENCODING, store_crl_info.Issuer, 2, buffer, buf_size)
                    issuer = String(buffer[1:retval - 1])
                    println(issuer)
                end

                ret = ccall((:mbedtls_x509_crl_parse, libmbedx509), Cint,
                    (Ptr{Cvoid}, Ptr{UInt8}, Csize_t),
                    config.crl_chain.data, store_crl.pbCrlEncoded, store_crl.cbCrlEncoded)
            end

            pccrl_context = ccall((:CertEnumCRLsInStore, _crypt32), PCCRL_CONTEXT, (HCERTSTORE, PCCRL_CONTEXT),
                hcertstore, pccrl_context)

            last_error = Libc.GetLastError()
            count += 1
        end

        if debug_output
            @show count
        end

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
