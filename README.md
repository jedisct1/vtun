This is a fork of [VTUN](http://vtun.sourceforge.net/), with the
following changes:

* OpenSSL was replaced with libsodium. This requires libsodium >= 1.0.6.

* Unauthenticated encryption schemes were replaced with hardware-accelerated
AES256-GCM.

* The static, shared key was replaced by an ephemeral keys exchange with
Curve25519. The PSK is now only used to sign ephemeral public keys and
parameters.

* Protection against replay attacks was added.

* Passwords are not kept in memory, guarded memory allocations are
used for secrets.
