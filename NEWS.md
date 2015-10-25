MbedTLS v0.2.0 Release Notes
=====

New features
---

* Support for symmetric encryption ([#9]) via the `encrypt` and `decrypt` functions

* Support for [HMAC] and non-HMAC [message digests]
([#9]):
```julia
julia> digest(MD_SHA256, "my message", "secret key")
32-element Array{UInt8,1}:
 0x62
 0x31
 0x3b
 0xfa
 0x9b
 0x36
 0x81
 0xa7
 0x85
 0x21
    ⋮
 0xbe
 0x32
 0x69
 0x3d
 0x57
 0x9a
 0xa2
 0xe1
 0x31
 0xc4
```
* User-facing functions for RSA key generation


Deprecations
---
* The `hash` family of functions have been replaced by `digest` functions to
reflect the terminology used in MbedTLS.

MbedTLS v0.1.0 Release Notes
====

New features
---
* Support for cryptographic random number generator, CtrDrpg
* SSL support
* x509 certificate parsing and generation

[#9]: https://github.com/JuliaWeb/MbedTLS.jl/issues/9
[HMAC]: https://en.wikipedia.org/wiki/Hash-based_message_authentication_code
[message digests]: https://en.wikipedia.org/wiki/Cryptographic_hash_function
