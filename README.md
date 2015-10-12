This is a fork of [VTUN](http://vtun.sourceforge.net/), with the
following changes:

* OpenSSL was replaced by Libsodium (this currently requires code from
the [git repository](https://github.com/jedisct1/libsodium) to be
compiled until version 1.0.4 is out).

* Unauthenticated encryption schemes were replaced with aesni and
pclmulqdq-accelerated AES256-GCM.

* Protection against replay attacks was added.

* More secure key derivation and initial handshake.

* Passwords are not kept in memory.

* Guarded memory allocations for secrets.
