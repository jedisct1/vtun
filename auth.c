/*
 * Key exchange
 *
 * Client <-> Server
 *
 * -> "CKEY "  || host || " " || ts || Cpk || Hk(ts || Cpk)
 * <- "SKEY "  || Spk || Hk(Spk || Hk(ts || Cpk))
 * -> "CACK "  || Hk("CACK" || Hk(Spk || Hk(ts || Cpk)))
 * <- "FLAGS " || flags || " " || Hk(flags || Hk("CACK" || Hk(Spk || Hk(ts || Cpk))))
 *
 * session_key = Hk(DH)
 *
 * ts: current timestamp, 4 big-endian bytes
 * (Cpk, Csk): client public/secret ephemeral key pair
 * (Spk, Ssk): server public/secret ephemeral key pair
 * Hk: keyed hash function, key derived from the PSK
 *
 * DH function: Curve25519
 * Keyed hash function: Blake2b
 * KDF: Scrypt
 */

#include "config.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <time.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <sodium.h>

#include "vtun.h"
#include "lib.h"
#include "lock.h"
#include "auth.h"

static int derive_key(struct vtun_host *host)
{
    unsigned char salt[crypto_pwhash_scryptsalsa208sha256_SALTBYTES];
    int ret = -1;
    size_t bin_len;

    if (host->akey != NULL) {
        return 0;
    }
    if ((host->akey = sodium_malloc(crypto_generichash_KEYBYTES)) == NULL) {
        return -1;
    }
    memset(salt, 0xd1, sizeof salt);
    if (crypto_pwhash_scryptsalsa208sha256(host->akey, HOST_KEYBYTES,
                                           host->passwd, strlen(host->passwd), salt,
                                           crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
                                           crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE) == 0) {
        ret = 0;
    }
    sodium_memzero(host->passwd, strlen(host->passwd));
    free(host->passwd);
    host->passwd = NULL;
    vtun_syslog(LOG_DEBUG, "Key ready for host [%s]", host->host);

    return ret;
}

/*
 * Functions to convert binary flags to character string.
 * string format:  <CS64>
 * C - compression, S - speed for shaper and so on.
 */

static char *bf2cf(struct vtun_host *host)
{
    static char str[32], * ptr = str;

    *(ptr++) = '<';

    switch (host->flags & VTUN_PROT_MASK) {
    case VTUN_TCP:
        *(ptr++) = 'T';
        break;

    case VTUN_UDP:
        *(ptr++) = 'U';
        break;
    }
    switch (host->flags & VTUN_TYPE_MASK) {
    case VTUN_TTY:
        *(ptr++) = 't';
        break;
    case VTUN_PIPE:
        *(ptr++) = 'p';
        break;
    case VTUN_ETHER:
        *(ptr++) = 'e';
        break;
    case VTUN_TUN:
        *(ptr++) = 'u';
        break;
    }
    if ((host->flags & VTUN_SHAPE) /* && host->spd_in */)
        ptr += sprintf(ptr, "S%d", host->spd_in);

    if (host->flags & VTUN_ZLIB)
        ptr += sprintf(ptr, "C%d", host->zlevel);

    if (host->flags & VTUN_LZO)
        ptr += sprintf(ptr, "L%d", host->zlevel);

    if (host->flags & VTUN_KEEP_ALIVE)
        *(ptr++) = 'K';

    if (host->flags & VTUN_ENCRYPT) {
        ptr += sprintf(ptr, "E%d", host->cipher);
    }

    strcat(ptr, ">");

    return str;
}

/*
 * return 0 on success, otherwise -1
 *  Example: FLAGS: <TuE1>
 */
static int cf2bf(char *str, struct vtun_host *host)
{
    char *ptr, *p;
    int s;

    if (strlen(str) >= 32) {
        return -1;
    }
    if ((ptr = strchr(str, '<'))) {
        vtun_syslog(LOG_DEBUG, "Remote Server sends %s.", ptr);
        ptr++;
        while (*ptr) {
            switch (*ptr++) {
            case 't':
                host->flags |= VTUN_TTY;
                break;
            case 'p':
                host->flags |= VTUN_PIPE;
                break;
            case 'e':
                host->flags |= VTUN_ETHER;
                break;
            case 'u':
                host->flags |= VTUN_TUN;
                break;
            case 'U':
                host->flags &= ~VTUN_PROT_MASK;
                host->flags |= VTUN_UDP;
                break;
            case 'T':
                host->flags &= ~VTUN_PROT_MASK;
                host->flags |= VTUN_TCP;
                break;
            case 'K':
                host->flags |= VTUN_KEEP_ALIVE;
                break;
            case 'C':
                if ((s = strtol(ptr, &p, 10)) == ERANGE || ptr == p) {
                    return -1;
                }
                host->flags |= VTUN_ZLIB;
                host->zlevel = s;
                ptr = p;
                break;
            case 'L':
                if ((s = strtol(ptr, &p, 10)) == ERANGE || ptr == p) {
                    return -1;
                }
                host->flags |= VTUN_LZO;
                host->zlevel = s;
                ptr = p;
                break;
            case 'E':
                /* new form is 'E10', old form is 'E', so remove the
                   ptr==p check */
                if ((s = strtol(ptr, &p, 10)) == ERANGE) {
                    vtun_syslog(LOG_ERR, "Garbled encryption method. Bailing out.");
                    return -1;
                }
                host->flags |= VTUN_ENCRYPT;
                host->cipher = s;
                ptr = p;
                break;
            case 'S':
                if ((s = strtol(ptr, &p, 10)) == ERANGE || ptr == p) {
                    return -1;
                }
                if (s > 0) {
                    host->flags |= VTUN_SHAPE;
                    host->spd_out = s;
                }
                ptr = p;
                break;
            case 'F':
                /* reserved for Feature transmit */
                break;
            case '>':
                return 0;
            default:
                return -1;
            }
        }
    }
    return -1;
}

/* Authentication (Server side) */
struct vtun_host *auth_server(int fd)
{
    char          buf[VTUN_MESG_SIZE], *str1, *str2, *str3;
    unsigned char cack[crypto_generichash_BYTES];
    unsigned char client_pk[crypto_scalarmult_BYTES];
    unsigned char server_pk[crypto_scalarmult_BYTES];
    unsigned char server_sk[crypto_scalarmult_SCALARBYTES];
    unsigned char ckey[4 + crypto_scalarmult_BYTES + crypto_generichash_BYTES];
    unsigned char dhkey[crypto_scalarmult_BYTES];
    unsigned char skey[crypto_scalarmult_BYTES + crypto_generichash_BYTES];
    char          skey_hex[2 * (crypto_scalarmult_BYTES + crypto_generichash_BYTES) + 1];
    unsigned char hash[crypto_generichash_BYTES];
    unsigned char flhash[crypto_generichash_BYTES];
    char          flhash_hex[2 * crypto_generichash_BYTES + 1];
    struct        vtun_host *host = NULL;
    char         *flags;
    char         *host_name = NULL;
    crypto_generichash_state st;
    time_t        client_now;
    size_t        bin_len;
    int           stage;
    int           success = 0;

    set_title("authentication");

    print_p(fd, "VTUN server ver %s\n", VTUN_VER);

    stage = ST_STEP2;

    while (readn_t(fd, buf, VTUN_MESG_SIZE, vtun.timeout) > 0) {
        buf[sizeof(buf) - 1] = '\0';
        strtok(buf, "\r\n");
        if (!(str1 = strtok(buf, " :"))) {
            break;
        }
        if (!(str2 = strtok(NULL, " :"))) {
            break;
        }
        switch (stage) {
        case ST_STEP2:
            if (!strcmp(str1, "CKEY")) {
                if (!(str3 = strtok(NULL, " \t"))) {
                    break;
                }
                sodium_hex2bin(ckey, sizeof ckey, str3, strlen(str3), "", &bin_len, NULL);
                if (bin_len != sizeof ckey) {
                    break;
                }
                client_now = ((time_t) ckey[0]) << 24 | ((time_t) ckey[1]) << 16 |
                    ((time_t) ckey[2]) << 9 | ((time_t) ckey[3]);
                (void) client_now;
                host_name = str2;
                if ((host = find_host(host_name)) == NULL || derive_key(host) != 0) {
                    break;
                }
                crypto_generichash(hash, sizeof hash,
                                   ckey, 4 + crypto_scalarmult_BYTES,
                                   host->akey, crypto_generichash_KEYBYTES);
                if (sodium_memcmp(hash, ckey + 4 + crypto_scalarmult_BYTES, sizeof hash) != 0) {
                    break;
                }
                memcpy(client_pk, ckey + 4, sizeof client_pk);
                randombytes_buf(server_sk, crypto_scalarmult_SCALARBYTES);
                crypto_scalarmult_base(server_pk, server_sk);
                memcpy(skey, server_pk, sizeof server_pk);
                memcpy(skey + crypto_scalarmult_BYTES, hash, sizeof hash);
                crypto_generichash(skey + crypto_scalarmult_BYTES, crypto_scalarmult_BYTES,
                                   skey, sizeof skey,
                                   host->akey, crypto_generichash_KEYBYTES);
                sodium_bin2hex(skey_hex, sizeof skey_hex, skey, sizeof skey);
                print_p(fd, "SKEY: %s\n", skey_hex);
                stage = ST_STEP3;
                continue;
            }
            break;

        case ST_STEP3:
            if (!strcmp(str1, "CACK")) {
                sodium_hex2bin(cack, sizeof cack, str2, strlen(str2), "", &bin_len, NULL);
                if (bin_len != sizeof cack) {
                    break;
                }
                crypto_generichash_init(&st, host->akey, crypto_generichash_KEYBYTES,
                                        crypto_generichash_BYTES);
                crypto_generichash_update(&st, (const unsigned char *) "CACK", 4);
                crypto_generichash_update(&st, skey, sizeof skey);
                crypto_generichash_final(&st, hash, sizeof hash);
                if (sodium_memcmp(hash, cack, sizeof hash) != 0) {
                    break;
                }
                /* Lock host */
                if (lock_host(host) < 0) {
                    /* Multiple connections are denied */
                    host = NULL;
                    break;
                }
                flags = bf2cf(host);
                crypto_generichash_init(&st, host->akey, crypto_generichash_KEYBYTES,
                                        crypto_generichash_BYTES);
                crypto_generichash_update(&st, (const unsigned char *) flags, strlen(flags));
                crypto_generichash_update(&st, cack, sizeof cack);
                crypto_generichash_final(&st, flhash, sizeof flhash);
                sodium_bin2hex(flhash_hex, sizeof flhash_hex, flhash, sizeof flhash);
                print_p(fd, "FLAGS: %s %s\n", flags, flhash_hex);

                if (crypto_scalarmult(dhkey, server_sk, client_pk) != 0) {
                    break;
                }
                sodium_memzero(server_sk, sizeof server_sk);
                if ((host->key = sodium_malloc(HOST_KEYBYTES)) == NULL) {
                    abort();
                }
                crypto_generichash(host->key, HOST_KEYBYTES, dhkey, sizeof dhkey,
                                   host->akey, crypto_generichash_KEYBYTES);
                sodium_memzero(dhkey, sizeof dhkey);
                success = 1;
            }
            break;
        }
        break;
    }
    if (success == 0) {
        print_p(fd, "ERR\n");
        host = NULL;
    }
    return host;
}

/* Authentication (Client side) */
int auth_client(int fd, struct vtun_host *host)
{
    char          buf[VTUN_MESG_SIZE], *str1, *str2, *str3;
    unsigned char cack[crypto_generichash_BYTES];
    char          cack_hex[2 * crypto_generichash_BYTES + 1];
    unsigned char flhash[crypto_generichash_BYTES];
    unsigned char hash[crypto_generichash_BYTES];
    unsigned char client_pk[crypto_scalarmult_BYTES];
    unsigned char client_sk[crypto_scalarmult_SCALARBYTES];
    unsigned char server_pk[crypto_scalarmult_BYTES];
    unsigned char dhkey[crypto_scalarmult_BYTES];
    unsigned char ckey[4 + crypto_scalarmult_BYTES + crypto_generichash_BYTES];
    char          ckey_hex[2 * (4 + crypto_scalarmult_BYTES + crypto_generichash_BYTES) + 1];
    unsigned char skey[crypto_scalarmult_BYTES + crypto_generichash_BYTES];
    crypto_generichash_state st;
    time_t        now;
    size_t        bin_len;
    int           stage;
    int           success = 0;

    stage = ST_INIT;

    if (derive_key(host) != 0) {
        return 0;
    }
    while (readn_t(fd, buf, VTUN_MESG_SIZE, vtun.timeout) > 0) {
        buf[sizeof(buf) - 1] = '\0';
        strtok(buf, "\r\n");
        if (!(str1 = strtok(buf, " :"))) {
            break;
        }
        if (!(str2 = strtok(NULL, " :"))) {
            break;
        }
        switch (stage) {
        case ST_INIT:
            if (!strcmp(str1, "VTUN")) {
                now = time(NULL);
                randombytes_buf(client_sk, crypto_scalarmult_SCALARBYTES);
                crypto_scalarmult_base(client_pk, client_sk);
                ckey[0] = (unsigned char)(now >> 24);
                ckey[1] = (unsigned char)(now >> 16);
                ckey[2] = (unsigned char)(now >> 8);
                ckey[3] = (unsigned char)(now);
                memcpy(ckey + 4, client_pk, crypto_scalarmult_BYTES);
                crypto_generichash(ckey + 4 + crypto_scalarmult_BYTES, crypto_generichash_BYTES,
                                   ckey, 4 + crypto_scalarmult_BYTES,
                                   host->akey, crypto_generichash_KEYBYTES);
                sodium_bin2hex(ckey_hex, sizeof ckey_hex, ckey, sizeof ckey);
                stage = ST_STEP2;
                print_p(fd, "CKEY: %s %s\n", host->host, ckey_hex);
                continue;
            }
            break;

        case ST_STEP2:
            if (!strcmp(str1, "SKEY")) {
                sodium_hex2bin(skey, sizeof skey, str2, strlen(str2), "", &bin_len, NULL);
                if (bin_len != sizeof skey) {
                    break;
                }
                crypto_generichash_init(&st, host->akey, crypto_generichash_KEYBYTES,
                                        crypto_generichash_BYTES);
                crypto_generichash_update(&st, skey, crypto_scalarmult_BYTES);
                crypto_generichash_update(&st, ckey + 4 + crypto_scalarmult_BYTES,
                                          crypto_generichash_BYTES);
                crypto_generichash_final(&st, hash, sizeof hash);
                if (sodium_memcmp(hash, skey + crypto_scalarmult_BYTES, sizeof hash) != 0) {
                    break;
                }
                memcpy(server_pk, skey, sizeof server_pk);
                crypto_generichash_init(&st, host->akey, crypto_generichash_KEYBYTES,
                                        crypto_generichash_BYTES);
                crypto_generichash_update(&st, (const unsigned char *) "CACK", 4);
                crypto_generichash_update(&st, skey, sizeof skey);
                crypto_generichash_final(&st, cack, sizeof cack);
                sodium_bin2hex(cack_hex, sizeof cack_hex, cack, sizeof cack);
                print_p(fd, "CACK: %s\n", cack_hex);
                stage = ST_STEP3;
                continue;
            }
            break;

        case ST_STEP3:
            if (!strcmp(str1, "FLAGS")) {
                if (!(str3 = strtok(NULL, " \t"))) {
                    break;
                }
                sodium_hex2bin(flhash, sizeof flhash, str3, strlen(str3), "", &bin_len, NULL);
                if (bin_len != sizeof flhash) {
                    break;
                }
                if (cf2bf(str2, host) != 0) {
                    break;
                }
                crypto_generichash_init(&st, host->akey, crypto_generichash_KEYBYTES,
                                        crypto_generichash_BYTES);
                crypto_generichash_update(&st, (const unsigned char *) str2, strlen(str2));
                crypto_generichash_update(&st, cack, sizeof cack);
                crypto_generichash_final(&st, hash, sizeof hash);
                if (sodium_memcmp(hash, flhash, sizeof hash) != 0) {
                    break;
                }
                if (crypto_scalarmult(dhkey, client_sk, server_pk) != 0) {
                    break;
                }
                sodium_memzero(client_sk, sizeof client_sk);
                if ((host->key = sodium_malloc(HOST_KEYBYTES)) == NULL) {
                    abort();
                }
                crypto_generichash(host->key, HOST_KEYBYTES, dhkey, sizeof dhkey,
                                   host->akey, crypto_generichash_KEYBYTES);
                sodium_memzero(dhkey, sizeof dhkey);
                success = 1;
            }
            break;
        }
        break;
    }

    return success;
}
