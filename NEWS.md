MbedTLS v0.2.0 Release Notes
=====

New features
---

* Support for symmetric encryption  via the `encrypt` and `decrypt` functions. ([#9])
* Support for [HMAC] and non-HMAC [message digests]. ([#9])
* User-facing functions for RSA key generation.


Deprecations
---
* The `hash` family of functions have been replaced by `digest` functions to
reflect the terminology used in MbedTLS.

MbedTLS v0.1.0 Release Notes
====

New features
---
* Support for cryptographic random number generator, CtrDrpg.
* SSL support.
* x509 certificate parsing and generation.

[#9]: https://github.com/JuliaWeb/MbedTLS.jl/issues/9
[HMAC]: https://en.wikipedia.org/wiki/Hash-based_message_authentication_code
[message digests]: https://en.wikipedia.org/wiki/Cryptographic_hash_function
