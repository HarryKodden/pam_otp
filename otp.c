/* Copyright (C) 2018 Harry Kodden
 */
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <gcrypt.h>
#include <stdint.h>

#include "base32.h"

static int DIGITS_POWER[] = {1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000};

static int Truncate (int Mode, unsigned char *hmac, int N) {

    int O = 0;

    switch (Mode) {
    case GCRY_MD_SHA256:
        O = (hmac[31] & 0x0f);
        break;
    case GCRY_MD_SHA512:
        O = (hmac[63] & 0x0f);
        break;
    case GCRY_MD_SHA1:
    default:
        O = (hmac[19] & 0x0f);
        break;
    }

    int code = ((hmac[O] & 0x7f) << 24) | ((hmac[O + 1] & 0xff) << 16) | ((hmac[O + 2] & 0xff) << 8) | ((hmac[O + 3] & 0xff));
    int token = code % DIGITS_POWER[N];

    return token;
}

static int hexchr2bin(const char hex, char *out) {
    if (out == NULL)
        return 0;

    if (hex >= '0' && hex <= '9') {
        *out = hex - '0';
    } else if (hex >= 'A' && hex <= 'F') {
        *out = hex - 'A' + 10;
    } else if (hex >= 'a' && hex <= 'f') {
        *out = hex - 'a' + 10;
    } else {
        return 0;
    }

    return 1;
}

static size_t hex2bin(const char *hex, unsigned char **out) {
    size_t len;
    char   b1;
    char   b2;
    size_t i;

    if (hex == NULL || *hex == '\0' || out == NULL)
        return 0;

    len = strlen(hex);
    if (len % 2 != 0)
        return 0;
    len /= 2;

    *out = malloc(len);
    memset(*out, 'A', len);
    for (i = 0; i < len; i++) {
        if (!hexchr2bin(hex[i * 2], &b1) || !hexchr2bin(hex[i * 2 + 1], &b2)) {
            return 0;
        }
        (*out)[i] = (b1 << 4) | b2;
    }

    return len;
}

static char *bin2hex(long data, short bytes) {
    char *buffer = NULL;

    asprintf(&buffer, "%0*.*lX", bytes, bytes, data);
    return buffer;
}

static unsigned char *HMAC (int Mode, char *Key, long C) {
    char *tmp = bin2hex(C, 16);

    unsigned char *msg;
    size_t len = hex2bin(tmp, &msg);
    free(tmp);

    gcry_md_hd_t hd;
    gcry_md_open (&hd, Mode, GCRY_MD_FLAG_HMAC);
    gcry_md_setkey (hd, Key, strlen(Key));
    gcry_md_write (hd, msg, len);
    gcry_md_final (hd);
    unsigned char *hmac =  gcry_md_read (hd, Mode);

    free(msg);
    return hmac;
}

static int HOTP (int Mode, char *Key, long C, int N) {
    unsigned char *hmac = HMAC(Mode, Key, C);
    int token = Truncate (Mode, hmac, N);
    return token;
}

static int TOTP (int Mode, char *Key, long epoch, int N) {
    return HOTP(Mode, Key, epoch/30, N);
}

int token (char *secret, long epoch) {
    char decoded[1024];
    base32_decode(secret, decoded);

    fprintf(stderr, "Base32 decode: \"%s\" -> \"%s\"\n", secret, decoded);
    return TOTP(GCRY_MD_SHA1, decoded, epoch, 6);
}

int valid_token(char *secret, long epoch, int my_token) {
    return (my_token == token(secret, epoch));
}

/*
 * Ref: https://tools.ietf.org/html/rfc6238#appendix-B

  +-------------+--------------+------------------+----------+--------+
  |  Time (sec) |   UTC Time   | Value of T (hex) |   TOTP   |  Mode  |
  +-------------+--------------+------------------+----------+--------+
  |      59     |  1970-01-01  | 0000000000000001 | 94287082 |  SHA1  |
  |             |   00:00:59   |                  |          |        |
  |      59     |  1970-01-01  | 0000000000000001 | 46119246 | SHA256 |
  |             |   00:00:59   |                  |          |        |
  |      59     |  1970-01-01  | 0000000000000001 | 90693936 | SHA512 |
  |             |   00:00:59   |                  |          |        |
  |  1111111109 |  2005-03-18  | 00000000023523EC | 07081804 |  SHA1  |
  |             |   01:58:29   |                  |          |        |
  |  1111111109 |  2005-03-18  | 00000000023523EC | 68084774 | SHA256 |
  |             |   01:58:29   |                  |          |        |
  |  1111111109 |  2005-03-18  | 00000000023523EC | 25091201 | SHA512 |
  |             |   01:58:29   |                  |          |        |
  |  1111111111 |  2005-03-18  | 00000000023523ED | 14050471 |  SHA1  |
  |             |   01:58:31   |                  |          |        |
  |  1111111111 |  2005-03-18  | 00000000023523ED | 67062674 | SHA256 |
  |             |   01:58:31   |                  |          |        |
  |  1111111111 |  2005-03-18  | 00000000023523ED | 99943326 | SHA512 |
  |             |   01:58:31   |                  |          |        |
  |  1234567890 |  2009-02-13  | 000000000273EF07 | 89005924 |  SHA1  |
  |             |   23:31:30   |                  |          |        |
  |  1234567890 |  2009-02-13  | 000000000273EF07 | 91819424 | SHA256 |
  |             |   23:31:30   |                  |          |        |
  |  1234567890 |  2009-02-13  | 000000000273EF07 | 93441116 | SHA512 |
  |             |   23:31:30   |                  |          |        |
  |  2000000000 |  2033-05-18  | 0000000003F940AA | 69279037 |  SHA1  |
  |             |   03:33:20   |                  |          |        |
  |  2000000000 |  2033-05-18  | 0000000003F940AA | 90698825 | SHA256 |
  |             |   03:33:20   |                  |          |        |
  |  2000000000 |  2033-05-18  | 0000000003F940AA | 38618901 | SHA512 |
  |             |   03:33:20   |                  |          |        |
  | 20000000000 |  2603-10-11  | 0000000027BC86AA | 65353130 |  SHA1  |
  |             |   11:33:20   |                  |          |        |
  | 20000000000 |  2603-10-11  | 0000000027BC86AA | 77737706 | SHA256 |
  |             |   11:33:20   |                  |          |        |
  | 20000000000 |  2603-10-11  | 0000000027BC86AA | 47863826 | SHA512 |
  |             |   11:33:20   |                  |          |        |
  +-------------+--------------+------------------+----------+--------+
*/

struct REFERENCE {
    int Mode;
    long Time;
    long TOTP;
} references[] = {
    { GCRY_MD_SHA1, 59, 94287082 },
    { GCRY_MD_SHA256, 59, 46119246 },
    { GCRY_MD_SHA512, 59, 90693936 },

    { GCRY_MD_SHA1, 1111111109, 7081804 },
    { GCRY_MD_SHA256, 1111111109, 68084774 },
    { GCRY_MD_SHA512, 1111111109, 25091201 },

    { GCRY_MD_SHA1, 1111111111, 14050471 },
    { GCRY_MD_SHA256, 1111111111, 67062674 },
    { GCRY_MD_SHA512, 1111111111, 99943326 },

    { GCRY_MD_SHA1, 1234567890, 89005924 },
    { GCRY_MD_SHA256, 1234567890, 91819424 },
    { GCRY_MD_SHA512, 1234567890, 93441116 },
    
    { GCRY_MD_SHA1, 2000000000, 69279037 },
    { GCRY_MD_SHA256, 2000000000, 90698825 },
    { GCRY_MD_SHA512, 2000000000, 38618901 },
    
    { GCRY_MD_SHA1, 20000000000, 65353130 },
    { GCRY_MD_SHA256, 20000000000, 77737706 },
    { GCRY_MD_SHA512, 20000000000, 47863826 }
};

static char *test_seed(int bytes) {

    char *buffer = malloc(bytes+1);
    int i;
    for (i=0; i<bytes; i++) {
       *(buffer+i) = (((i+1)%10)+'0') & 0xff;
       *(buffer+i+1) = '\0';
    }

    return buffer;
}

static void test_goal(int n, struct REFERENCE r) {
    char *my_secret;

    char *s = strdup(ctime(&r.Time));
    s[strlen(s)-1] = '\0'; // Remove trailing '\n'
    fprintf(stderr, "TEST[%d]: epoch: %ld, \"%s\"", n+1, r.Time, s);
    free(s);

    switch (r.Mode) {
    case GCRY_MD_SHA256:
        fprintf(stderr, ", SHA256");
        my_secret = test_seed(32);
        break;
    case GCRY_MD_SHA512:
        fprintf(stderr, ", SHA512");
        my_secret = test_seed(64);
        break;
    case GCRY_MD_SHA1:
    default:
        fprintf(stderr, ", SHA1");
        my_secret = test_seed(20);
        break;
    }

    int totp = HOTP(r.Mode, my_secret, r.Time/30, 8);
    fprintf(stderr, ", calculated TOTP: %d", totp);

    if (totp != r.TOTP) {
        fprintf(stderr, ", NOT OK !");
    } else {
        fprintf(stderr, ", OK !");
    }

    fprintf(stderr, "\n");

    free(my_secret);
}

void self_test(void) {
    int i;

    for (i=0; i<(sizeof(references)/sizeof(references[0])); i++) {
        test_goal(i, references[i]);
    }
}
