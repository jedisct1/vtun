This is a fork of [VTUN](http://vtun.sourceforge.net/), with the
following changes:

* OpenSSL was replaced by Libsodium (this currently requires the
[aes256gcm](https://github.com/jedisct1/libsodium/tree/aes256gcm)
branch).

* Unauthenticated encryption schemes were replaced with aesni and
pclmulqdq-accelerated AES256-GCM.

* Protection against replay attacks was added.

* More secure key derivation and initial handshake.

* Passwords are not kept in memory.

* Guarded memory allocations for secrets.
