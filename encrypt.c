/*
 * encrypt.c - Manage the global encryptor
 *
 * Copyright (C) 2013 - 2014, Max Lv <max.c.lv@gmail.com>
 *
 * This file is part of the shadowsocks-libev.
 *
 * shadowsocks-libev is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * shadowsocks-libev is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with pdnsd; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifdef ENABLE_SS
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "encrypt.h"
#include <assert.h>
#include <stdint.h>

#if defined(USE_CRYPTO_OPENSSL)

#include <openssl/md5.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

#elif defined(USE_CRYPTO_MBEDTLS)

#include <mbedtls/md5.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/version.h>
#define CIPHER_UNSUPPORTED "unsupported"

#include <time.h>
#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <stdio.h>
#endif

#endif

#include "utils.h"

#define OFFSET_ROL(p, o) ((uint64_t)(*(p + o)) << (8 * o))

static uint8_t *enc_table;
static uint8_t *dec_table;
static uint8_t enc_key[MAX_KEY_LENGTH];
static int enc_key_len;
static int enc_method;

#ifdef DEBUG
static void dump(char *tag, char *text, int len)
{
    int i;
    printf("%s: ", tag);
    for (i = 0; i < len; i++) {
        printf("0x%02x ", (uint8_t)text[i]);
    }
    printf("\n");
}
#endif

#define FATAL(...) do \
{ \
    LOGE(__VA_ARGS__); \
    exit(-1); \
} while (0)

#ifdef USE_CRYPTO_MBEDTLS
# define _(mbedtls, cc) mbedtls
# ifdef USE_CRYPTO_APPLECC
#  define _(mbedtls, cc) mbedtls, cc
# endif
#else
# define _(mbedtls, cc) 
#endif

static struct {
    const char *name;
    const uint8_t key_size;
    const uint8_t iv_size;
    const uint8_t tag_size;
    const cipher_kt_t *cipher;
#ifdef USE_CRYPTO_MBEDTLS
    const char *cipher_mbedtls;
#endif
#ifdef USE_CRYPTO_APPLECC
    CCAlgorithm cipher_applecc;
#endif
} supported_ciphers[CIPHER_NUM] =
{
    // stream: tcp stream first rand bytes is iv
    {"table",              0,    0,   0, NULL, _("table",               CCAlgorithmInvalid) },
    {"rc4",               16,    0,   0, NULL, _("ARC4-128",            CCAlgorithmRC4)     },
    {"rc4-md5",           16,   16,   0, NULL, _("ARC4-128",            CCAlgorithmRC4)     },
    {"aes-128-cfb",       16,   16,   0, NULL, _("AES-128-CFB128",      CCAlgorithmAES)     },
    {"aes-192-cfb",       24,   16,   0, NULL, _("AES-192-CFB128",      CCAlgorithmAES)     },
    {"aes-256-cfb",       32,   16,   0, NULL, _("AES-256-CFB128",      CCAlgorithmAES)     },
    {"bf-cfb",            16,    8,   0, NULL, _("BLOWFISH-CFB64",      CCAlgorithmBlowfish)},
    {"camellia-128-cfb",  16,   16,   0, NULL, _("CAMELLIA-128-CFB128", CCAlgorithmInvalid) },
    {"camellia-192-cfb",  24,   16,   0, NULL, _("CAMELLIA-192-CFB128", CCAlgorithmInvalid) },
    {"camellia-256-cfb",  32,   16,   0, NULL, _("CAMELLIA-256-CFB128", CCAlgorithmInvalid) },
    {"cast5-cfb",         16,    8,   0, NULL, _(CIPHER_UNSUPPORTED,    CCAlgorithmCAST)    },
    {"des-cfb",            8,    8,   0, NULL, _(CIPHER_UNSUPPORTED,    CCAlgorithmDES)     },
    {"idea-cfb",          16,    8,   0, NULL, _(CIPHER_UNSUPPORTED,    CCAlgorithmInvalid) },
    {"rc2-cfb",           16,    8,   0, NULL, _(CIPHER_UNSUPPORTED,    CCAlgorithmRC2)     },
    {"seed-cfb",          16,   16,   0, NULL, _(CIPHER_UNSUPPORTED,    CCAlgorithmInvalid) },
    {"aes-128-ofb",       16,   16,   0, NULL, _(CIPHER_UNSUPPORTED,    CCAlgorithmInvalid) },
    {"aes-192-ofb",       24,   16,   0, NULL, _(CIPHER_UNSUPPORTED,    CCAlgorithmInvalid) },
    {"aes-256-ofb",       32,   16,   0, NULL, _(CIPHER_UNSUPPORTED,    CCAlgorithmInvalid) },
    {"aes-128-ctr",       16,   16,   0, NULL, _("AES-128-CTR",         CCAlgorithmInvalid) },
    {"aes-192-ctr",       24,   16,   0, NULL, _("AES-192-CTR",         CCAlgorithmInvalid) },
    {"aes-256-ctr",       32,   16,   0, NULL, _("AES-256-CTR",         CCAlgorithmInvalid) },
    {"aes-128-cfb8",      16,   16,   0, NULL, _(CIPHER_UNSUPPORTED,    CCAlgorithmInvalid) },
    {"aes-192-cfb8",      24,   16,   0, NULL, _(CIPHER_UNSUPPORTED,    CCAlgorithmInvalid) },
    {"aes-256-cfb8",      32,   16,   0, NULL, _(CIPHER_UNSUPPORTED,    CCAlgorithmInvalid) },
    {"aes-128-cfb1",      16,   16,   0, NULL, _(CIPHER_UNSUPPORTED,    CCAlgorithmInvalid) },
    {"aes-192-cfb1",      24,   16,   0, NULL, _(CIPHER_UNSUPPORTED,    CCAlgorithmInvalid) },
    {"aes-256-cfb1",      32,   16,   0, NULL, _(CIPHER_UNSUPPORTED,    CCAlgorithmInvalid) },
    {"chacha20",          32,   16,   0, NULL, _(CIPHER_UNSUPPORTED,    CCAlgorithmInvalid) },
    // AEAD: tcp stream first rand bytes = key len
    {"aes-128-gcm",       16,   12,  16, NULL, _("AES-128-GCM",         CCAlgorithmInvalid) },
    {"aes-192-gcm",       24,   12,  16, NULL, _("AES-192-GCM",         CCAlgorithmInvalid) },
    {"aes-256-gcm",       32,   12,  16, NULL, _("AES-256-GCM",         CCAlgorithmInvalid) },
    {"aes-128-ocb",       16,   12,  16, NULL, _(CIPHER_UNSUPPORTED,    CCAlgorithmInvalid) },
    {"aes-192-ocb",       24,   12,  16, NULL, _(CIPHER_UNSUPPORTED,    CCAlgorithmInvalid) },
    {"aes-256-ocb",       32,   12,  16, NULL, _(CIPHER_UNSUPPORTED,    CCAlgorithmInvalid) },
    {"chacha20-poly1305", 32,   12,  16, NULL, _(CIPHER_UNSUPPORTED,    CCAlgorithmInvalid) },
};

#undef _

static int random_compare(const void *_x, const void *_y, uint32_t i,
                          uint64_t a)
{
    uint8_t x = *((uint8_t *)_x);
    uint8_t y = *((uint8_t *)_y);
    return a % (x + i) - a % (y + i);
}

static void merge(uint8_t *left, int llength, uint8_t *right,
                  int rlength, uint32_t salt, uint64_t key)
{
    uint8_t *ltmp = (uint8_t *)malloc(llength * sizeof(uint8_t));
    uint8_t *rtmp = (uint8_t *)malloc(rlength * sizeof(uint8_t));

    uint8_t *ll = ltmp;
    uint8_t *rr = rtmp;

    uint8_t *result = left;

    memcpy(ltmp, left, llength * sizeof(uint8_t));
    memcpy(rtmp, right, rlength * sizeof(uint8_t));

    while (llength > 0 && rlength > 0) {
        if (random_compare(ll, rr, salt, key) <= 0) {
            *result = *ll;
            ++ll;
            --llength;
        } else {
            *result = *rr;
            ++rr;
            --rlength;
        }
        ++result;
    }

    if (llength > 0) {
        while (llength > 0) {
            *result = *ll;
            ++result;
            ++ll;
            --llength;
        }
    } else {
        while (rlength > 0) {
            *result = *rr;
            ++result;
            ++rr;
            --rlength;
        }
    }

    free(ltmp);
    free(rtmp);
}

static void merge_sort(uint8_t array[], int length,
                       uint32_t salt, uint64_t key)
{
    uint8_t middle;
    uint8_t *left, *right;
    int llength;

    if (length <= 1) {
        return;
    }

    middle = length / 2;

    llength = length - middle;

    left = array;
    right = array + llength;

    merge_sort(left, llength, salt, key);
    merge_sort(right, middle, salt, key);
    merge(left, llength, right, middle, salt, key);
}

int enc_get_iv_len()
{
    return supported_ciphers[enc_method].iv_size;
}

int enc_get_key_len()
{
    return supported_ciphers[enc_method].key_size;
}

int enc_get_tag_len()
{
    return supported_ciphers[enc_method].tag_size;
}

unsigned char *enc_md5(const unsigned char *d, size_t n, unsigned char *md)
{
#if defined(USE_CRYPTO_OPENSSL)
    return MD5(d, n, md);
#elif defined(USE_CRYPTO_MBEDTLS)
    static unsigned char m[16];
    if (md == NULL) {
        md = m;
    }
    mbedtls_md5(d, n, md);
    return md;
#endif
}

void enc_table_init(const char *pass)
{
    uint32_t i;
    uint32_t salt;
    uint64_t key = 0;
    uint8_t *digest;

    enc_table = malloc(256);
    dec_table = malloc(256);

    digest = enc_md5((const uint8_t *)pass, strlen(pass), NULL);

    for (i = 0; i < 8; i++) {
        key += OFFSET_ROL(digest, i);
    }

    for (i = 0; i < 256; ++i) {
        enc_table[i] = i;
    }
    for (i = 1; i < 1024; ++i) {
        salt = i;
        merge_sort(enc_table, 256, salt, key);
    }
    for (i = 0; i < 256; ++i) {
        // gen decrypt table from encrypt table
        dec_table[enc_table[i]] = i;
    }
}

int cipher_iv_size(const cipher_kt_t *cipher)
{
#if defined(USE_CRYPTO_OPENSSL)
    return EVP_CIPHER_iv_length(cipher);
#elif defined(USE_CRYPTO_MBEDTLS)
    if (cipher == NULL) {
        return 0;
    }
    return cipher->iv_size;
#endif
}

int cipher_key_size(const cipher_kt_t *cipher)
{
#if defined(USE_CRYPTO_OPENSSL)
    return EVP_CIPHER_key_length(cipher);
#elif defined(USE_CRYPTO_MBEDTLS)
    if (cipher == NULL) {
        return 0;
    }
#if MBEDTLS_VERSION_NUMBER < 0x01020700
    /* Override mbed TLS 32 bit default key size with sane 128 bit default */
    if (cipher->type == MBEDTLS_CIPHER_BLOWFISH_CFB64) {
        return 128 / 8;
    }
#endif
    return cipher->key_bitlen / 8;
#endif
}

int bytes_to_key(const cipher_kt_t *cipher, const digest_type_t *md,
                 const uint8_t *pass, uint8_t *key, uint8_t *iv)
{
    size_t datal;
    datal = strlen((const char *)pass);
#if defined(USE_CRYPTO_OPENSSL)
    return EVP_BytesToKey(cipher, md, NULL, pass, datal, 1, key, iv);
#elif defined(USE_CRYPTO_MBEDTLS)
    mbedtls_md_context_t c;
    unsigned char md_buf[MAX_MD_SIZE];
    int niv;
    int nkey;
    int addmd;
    unsigned int mds;
    unsigned int i;
    int rv;

    nkey = cipher_key_size(cipher);
    niv = cipher_iv_size(cipher);
    rv = nkey;
    if (pass == NULL) {
        return nkey;
    }

    mbedtls_md_init(&c);
    if (mbedtls_md_setup(&c, md, 0)) {
        return 0;
    }
    addmd = 0;
    mds = mbedtls_md_get_size(md);
    for (;; ) {
        int error;
        do {
            error = 1;
            if (mbedtls_md_starts(&c)) {
                break;
            }
            if (addmd) {
                if (mbedtls_md_update(&c, &(md_buf[0]), mds)) {
                    break;
                }
            } else {
                addmd = 1;
            }
            if (mbedtls_md_update(&c, pass, datal)) {
                break;
            }
            if (mbedtls_md_finish(&c, &(md_buf[0]))) {
                break;
            }
            error = 0;
        } while (0);
        if (error) {
            mbedtls_md_free(&c);
            memset(md_buf, 0, MAX_MD_SIZE);
            return 0;
        }

        i = 0;
        if (nkey) {
            for (;; ) {
                if (nkey == 0) {
                    break;
                }
                if (i == mds) {
                    break;
                }
                if (key != NULL) {
                    *(key++) = md_buf[i];
                }
                nkey--;
                i++;
            }
        }
        if (niv && (i != mds)) {
            for (;; ) {
                if (niv == 0) {
                    break;
                }
                if (i == mds) {
                    break;
                }
                if (iv != NULL) {
                    *(iv++) = md_buf[i];
                }
                niv--;
                i++;
            }
        }
        if ((nkey == 0) && (niv == 0)) {
            break;
        }
    }
    mbedtls_md_free(&c);
    memset(md_buf, 0, MAX_MD_SIZE);
    return rv;
#endif
}

int rand_bytes(uint8_t *output, int len)
{
#if defined(USE_CRYPTO_OPENSSL)
    return RAND_bytes(output, len);
#elif defined(USE_CRYPTO_MBEDTLS)
    static mbedtls_entropy_context ec = {0};
    static mbedtls_ctr_drbg_context cd_ctx = {0};
    static unsigned char rand_initialised = 0;
    const size_t blen = min(len, MBEDTLS_CTR_DRBG_MAX_REQUEST);

    if (!rand_initialised) {
#ifdef _WIN32
        HCRYPTPROV hProvider;
        union {
            unsigned __int64 seed;
            BYTE buffer[8];
        } rand_buffer;

        hProvider = 0;
        if (CryptAcquireContext(&hProvider, 0, 0, PROV_RSA_FULL, \
                                CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
            CryptGenRandom(hProvider, 8, rand_buffer.buffer);
            CryptReleaseContext(hProvider, 0);
        } else {
            rand_buffer.seed = (unsigned __int64)clock();
        }
#else
        FILE *urand;
        union {
            uint64_t seed;
            uint8_t buffer[8];
        } rand_buffer;

        urand = fopen("/dev/urandom", "r");
        if (urand) {
            fread(&rand_buffer.seed, sizeof(rand_buffer.seed), 1, urand);
            fclose(urand);
        } else {
            rand_buffer.seed = (uint64_t)clock();
        }
#endif
        mbedtls_entropy_init(&ec);
        mbedtls_ctr_drbg_init(&cd_ctx);
        if (mbedtls_ctr_drbg_seed(&cd_ctx, mbedtls_entropy_func, &ec,
                          (const unsigned char *)rand_buffer.buffer, 8) != 0) {
#if MBEDTLS_VERSION_NUMBER >= 0x01030000
            mbedtls_entropy_free(&ec);
#endif
            FATAL("Failed to initialize random generator");
        }
        rand_initialised = 1;
    }
    while (len > 0) {
        if (mbedtls_ctr_drbg_random(&cd_ctx, output, blen) != 0) {
            return 0;
        }
        output += blen;
        len -= blen;
    }
    return 1;
#endif
}

const cipher_kt_t *get_cipher_type(int method)
{
    if (method <= TABLE || method >= CIPHER_NUM) {
        LOGE("get_cipher_type(): Illegal method");
        return NULL;
    }
    if (method == RC4_MD5) {
        method = RC4;
    }

    const char *ciphername = supported_ciphers[method].name;
#if defined(USE_CRYPTO_OPENSSL)
    const cipher_kt_t *cipher = EVP_get_cipherbyname(ciphername);
    if (cipher == NULL) {
        LOGE("Cipher %s not found in OpenSSL library", ciphername);
        return cipher;
    }

    if (EVP_CIPHER_iv_length(cipher) != supported_ciphers[method].iv_size) {
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
        assert(EVP_CIPHER_flags(cipher) & EVP_CIPH_CUSTOM_IV);
        cipher = EVP_CIPHER_meth_dup(cipher);
        EVP_CIPHER_meth_set_iv_length(cipher, supported_ciphers[method].iv_size);
#else
        FATAL("Cipher iv length mismatch");
#endif
    }
    return cipher;
#elif defined(USE_CRYPTO_MBEDTLS)
    const char *mbedname = supported_ciphers[method].cipher_mbedtls;
    if (strcmp(mbedname, CIPHER_UNSUPPORTED) == 0) {
        LOGE("Cipher %s currently is not supported by mbed TLS library",
             ciphername);
        return NULL;
    }
    return mbedtls_cipher_info_from_string(mbedname);
#endif
}

const digest_type_t *get_digest_type(const char *digest)
{
    if (digest == NULL) {
        LOGE("get_digest_type(): Digest name is null");
        return NULL;
    }

#if defined(USE_CRYPTO_OPENSSL)
    return EVP_get_digestbyname(digest);
#elif defined(USE_CRYPTO_MBEDTLS)
    return mbedtls_md_info_from_string(digest);
#endif
}

void cipher_context_init(cipher_ctx_t *ctx, int method, int enc)
{
    if (method <= TABLE || method >= CIPHER_NUM) {
        LOGE("cipher_context_init(): Illegal method");
        return;
    }

    const char *ciphername = supported_ciphers[method].name;
#if defined(USE_CRYPTO_APPLECC)
    cipher_cc_t *cc = &ctx->cc;
    cc->cryptor = NULL;
    cc->cipher = supported_ciphers[method].cipher_applecc;
    if (cc->cipher == kCCAlgorithmInvalid) {
        cc->valid = kCCContextInvalid;
    } else {
        cc->valid = kCCContextValid;
        if (cc->cipher == kCCAlgorithmRC4) {
            cc->mode = kCCModeRC4;
            cc->padding = ccNoPadding;
        } else {
            cc->mode = kCCModeCFB;
            cc->padding = ccPKCS7Padding;
        }
        return;
    }
#endif

    const cipher_kt_t *cipher = supported_ciphers[method].cipher;
#if defined(USE_CRYPTO_OPENSSL)
    if (cipher == NULL) {
        LOGE("Cipher %s not found in OpenSSL library", ciphername);
        FATAL("Cannot initialize cipher");
    }

    cipher_evp_t *evp = EVP_CIPHER_CTX_new();
    if (evp == NULL) {
        FATAL("Cannot create cipher context");
    }
    EVP_CIPHER_CTX_init(evp);
    if (!EVP_CipherInit_ex(evp, cipher, NULL, NULL, NULL, enc)) {
        LOGE("Cannot initialize cipher %s", ciphername);
        exit(EXIT_FAILURE);
    }
    if (!EVP_CIPHER_CTX_set_key_length(evp, enc_key_len)) {
        EVP_CIPHER_CTX_free(evp);
        LOGE("Invalid key length: %d", enc_key_len);
        exit(EXIT_FAILURE);
    }
    if (method > RC4_MD5) {
        EVP_CIPHER_CTX_set_padding(evp, 1);
    }
    ctx->evp = evp;
#elif defined(USE_CRYPTO_MBEDTLS)
    cipher_evp_t *evp = &ctx->evp;
    if (cipher == NULL) {
        LOGE("Cipher %s not found in mbed TLS library", ciphername);
        FATAL("Cannot initialize mbed TLS cipher");
    }
    if (mbedtls_cipher_setup(evp, cipher) != 0) {
        FATAL("Cannot initialize mbed TLS cipher context");
    }
#endif
}

void cipher_context_set_iv(cipher_ctx_t *ctx, uint8_t *iv, size_t iv_len,
                           int enc)
{
    const unsigned char *true_key;
    if (iv == NULL) {
        LOGE("cipher_context_set_iv(): IV is null");
        return;
    }
    if (enc) {
        rand_bytes(iv, iv_len);
    }
    if (enc_method == RC4_MD5) {
        unsigned char key_iv[32];
        memcpy(key_iv, enc_key, 16);
        memcpy(key_iv + 16, iv, 16);
        true_key = enc_md5(key_iv, 32, NULL);
        iv_len = 0;
    } else {
        true_key = enc_key;
    }

#ifdef USE_CRYPTO_APPLECC
    cipher_cc_t *cc = &ctx->cc;
    if (cc->valid == kCCContextValid) {
        memcpy(cc->iv, iv, iv_len);
        memcpy(cc->key, true_key, enc_key_len);
        cc->iv_len = iv_len;
        cc->key_len = enc_key_len;
        cc->encrypt = enc ? kCCEncrypt : kCCDecrypt;
        if (cc->cryptor != NULL) {
            CCCryptorRelease(cc->cryptor);
            cc->cryptor = NULL;
        }

        CCCryptorStatus ret;
        ret = CCCryptorCreateWithMode(
            cc->encrypt,
            cc->mode,
            cc->cipher,
            cc->padding,
            cc->iv, cc->key, cc->key_len,
            NULL, 0, 0, 0,
            &cc->cryptor);
        if (ret != kCCSuccess) {
            if (cc->cryptor != NULL) {
                CCCryptorRelease(cc->cryptor);
                cc->cryptor = NULL;
            }
            FATAL("Cannot set CommonCrypto key and IV");
        }
        return;
    }
#endif

#if defined(USE_CRYPTO_OPENSSL)
    cipher_evp_t *evp = ctx->evp;
    if (evp == NULL) {
        LOGE("cipher_context_set_iv(): Cipher context is null");
        return;
    }
    if (!EVP_CipherInit_ex(evp, NULL, NULL, true_key, iv, enc)) {
        EVP_CIPHER_CTX_free(evp);
        FATAL("Cannot set key and IV");
    }
#elif defined(USE_CRYPTO_MBEDTLS)
    cipher_evp_t *evp = &ctx->evp;
    if (mbedtls_cipher_setkey(evp, true_key, enc_key_len * 8, enc) != 0) {
        mbedtls_cipher_free(evp);
        FATAL("Cannot set mbed TLS cipher key");
    }
#if MBEDTLS_VERSION_NUMBER >= 0x01030000
    if (mbedtls_cipher_set_iv(evp, iv, iv_len) != 0) {
        mbedtls_cipher_free(evp);
        FATAL("Cannot set mbed TLS cipher IV");
    }
    if (mbedtls_cipher_reset(evp) != 0) {
        mbedtls_cipher_free(evp);
        FATAL("Cannot finalize mbed TLS cipher context");
    }
#else
    if (cipher_reset(evp, iv) != 0) {
        mbedtls_cipher_free(evp);
        FATAL("Cannot set mbed TLS cipher IV");
    }
#endif
#endif

#ifdef DEBUG
    dump("IV", (char *)iv, iv_len);
#endif
}

void cipher_context_release(cipher_ctx_t *ctx)
{
#ifdef USE_CRYPTO_APPLECC
    cipher_cc_t *cc = &ctx->cc;
    if (cc->cryptor != NULL) {
        CCCryptorRelease(cc->cryptor);
        cc->cryptor = NULL;
    }
    if (cc->valid == kCCContextValid) {
        return;
    }
#endif

#if defined(USE_CRYPTO_OPENSSL)
    cipher_evp_t *evp = ctx->evp;
    EVP_CIPHER_CTX_free(evp);
#elif defined(USE_CRYPTO_MBEDTLS)
    cipher_evp_t *evp = &ctx->evp;
    mbedtls_cipher_free(evp);
#endif
}

static int cipher_context_update(cipher_ctx_t *ctx, uint8_t *output, int *olen,
                                 const uint8_t *input, int ilen)
{
#ifdef USE_CRYPTO_APPLECC
    cipher_cc_t *cc = &ctx->cc;
    if (cc->valid == kCCContextValid) {
        CCCryptorStatus ret;
        ret = CCCryptorUpdate(cc->cryptor, input, ilen, output,
                              ilen + BLOCK_SIZE, (size_t *)olen);
        return (ret == kCCSuccess) ? 1 : 0;
    }
#endif

#if defined(USE_CRYPTO_OPENSSL)
    cipher_evp_t *evp = ctx->evp;
    return EVP_CipherUpdate(evp, (uint8_t *)output, olen,
                            (const uint8_t *)input, (size_t)ilen);
#elif defined(USE_CRYPTO_MBEDTLS)
    cipher_evp_t *evp = &ctx->evp;
    return !mbedtls_cipher_update(evp, (const uint8_t *)input, (size_t)ilen,
                          (uint8_t *)output, (size_t *)olen);
#endif
}

char * ss_encrypt_all(int buf_size, char *plaintext, ssize_t *len, int method)
{
    if (method > TABLE) {
        cipher_ctx_t evp;
        cipher_context_init(&evp, method, 1);

        int c_len = *len + BLOCK_SIZE;
        int iv_len = enc_get_iv_len();
        int err = 0;
        char *ciphertext = malloc(max(iv_len + c_len, buf_size));

        uint8_t iv[MAX_IV_LENGTH];
        cipher_context_set_iv(&evp, iv, iv_len, 1);
        memcpy(ciphertext, iv, iv_len);

        err = cipher_context_update(&evp, (uint8_t *)(ciphertext + iv_len),
                                    &c_len, (const uint8_t *)plaintext, *len);

        if (!err) {
            free(ciphertext);
            free(plaintext);
            cipher_context_release(&evp);
            return NULL;
        }

#ifdef DEBUG
        dump("PLAIN", plaintext, *len);
        dump("CIPHER", ciphertext + iv_len, c_len);
#endif

        *len = iv_len + c_len;
        free(plaintext);
        cipher_context_release(&evp);

        return ciphertext;

    } else {
        char *begin = plaintext;
        while (plaintext < begin + *len) {
            *plaintext = (char)enc_table[(uint8_t)*plaintext];
            plaintext++;
        }
        return begin;
    }
}

char * ss_encrypt(char *ciphertext, char *plaintext, ssize_t *len,
                  struct enc_ctx *ctx)
{
    if (ctx != NULL) {
        int c_len = *len + BLOCK_SIZE;
        int iv_len = 0;
        int err = 0;
        //char *ciphertext = malloc(max(iv_len + c_len, buf_size));

        if (!ctx->init) {
            uint8_t iv[MAX_IV_LENGTH];
            iv_len = enc_get_iv_len();
            cipher_context_set_iv(&ctx->evp, iv, iv_len, 1);
            memcpy(ciphertext, iv, iv_len);
            ctx->init = 1;
        }

        err = cipher_context_update(&ctx->evp, (uint8_t *)(ciphertext + iv_len),
                                    &c_len, (const uint8_t *)plaintext, *len);
        if (!err) {
            //free(ciphertext);
            //free(plaintext);
            return NULL;
        }

#ifdef DEBUG
        dump("PLAIN", plaintext, *len);
        dump("CIPHER", ciphertext + iv_len, c_len);
#endif

        *len = iv_len + c_len;
        //free(plaintext);
        return ciphertext;
    } else {
        char *begin = ciphertext;
        while (ciphertext < begin + *len) {
            *ciphertext = (char)enc_table[(uint8_t)*plaintext];
            ciphertext++;
            plaintext++;
        }
        return begin;
    }
}

char * ss_decrypt_all(int buf_size, char *ciphertext, ssize_t *len, int method)
{
    if (method > TABLE) {
        cipher_ctx_t evp;
        cipher_context_init(&evp, method, 0);

        int p_len = *len + BLOCK_SIZE;
        int iv_len = enc_get_iv_len();
        int err = 0;
        char *plaintext = malloc(max(p_len, buf_size));

        uint8_t iv[MAX_IV_LENGTH];
        memcpy(iv, ciphertext, iv_len);
        cipher_context_set_iv(&evp, iv, iv_len, 0);

        err = cipher_context_update(&evp, (uint8_t *)plaintext, &p_len,
                                    (const uint8_t *)(ciphertext + iv_len),
                                    *len - iv_len);
        if (!err) {
            free(ciphertext);
            free(plaintext);
            cipher_context_release(&evp);
            return NULL;
        }

#ifdef DEBUG
        dump("PLAIN", plaintext, p_len);
        dump("CIPHER", ciphertext + iv_len, *len - iv_len);
#endif

        *len = p_len;
        free(ciphertext);
        cipher_context_release(&evp);
        return plaintext;
    } else {
        char *begin = ciphertext;
        while (ciphertext < begin + *len) {
            *ciphertext = (char)dec_table[(uint8_t)*ciphertext];
            ciphertext++;
        }
        return begin;
    }
}

char * ss_decrypt(char *plaintext, char *ciphertext, ssize_t *len,
                  struct enc_ctx *ctx)
{
    if (ctx != NULL) {
        int p_len = *len + BLOCK_SIZE;
        int iv_len = 0;
        int err = 0;
        //char *plaintext = malloc(max(p_len, buf_size));

        if (!ctx->init) {
            uint8_t iv[MAX_IV_LENGTH];
            iv_len = enc_get_iv_len();
            if (*len < iv_len) {
                return NULL;
            }
            memcpy(iv, ciphertext, iv_len);
            cipher_context_set_iv(&ctx->evp, iv, iv_len, 0);
            ctx->init = 1;
        }

        err = cipher_context_update(&ctx->evp, (uint8_t *)plaintext, &p_len,
                                    (const uint8_t *)(ciphertext + iv_len),
                                    *len - iv_len);

        if (!err) {
            //free(ciphertext);
            //free(plaintext);
            return NULL;
        }

#ifdef DEBUG
        dump("PLAIN", plaintext, p_len);
        dump("CIPHER", ciphertext + iv_len, *len - iv_len);
#endif

        *len = p_len;
        //free(ciphertext);
        return plaintext;
    } else {
        char *begin = plaintext;
        while (plaintext < begin + *len) {
            *plaintext = (char)dec_table[(uint8_t)*ciphertext];
            plaintext++;
            ciphertext++;
        }
        return begin;
    }
}

void enc_ctx_init(int method, struct enc_ctx *ctx, int enc)
{
    memset(ctx, 0, sizeof(struct enc_ctx));
    cipher_context_init(&ctx->evp, method, enc);
    ctx->aead = supported_ciphers[method].tag_size > 0;
}

void enc_key_init(int method, const char *pass)
{
    if (method <= TABLE || method >= CIPHER_NUM) {
        LOGE("enc_key_init(): Illegal method");
        return;
    }

#if defined(USE_CRYPTO_OPENSSL)
    OpenSSL_add_all_ciphers();
#endif

#if defined(USE_CRYPTO_MBEDTLS) && defined(USE_CRYPTO_APPLECC)
    cipher_kt_t cipher_info;
#endif

    uint8_t iv[MAX_IV_LENGTH];
    const cipher_kt_t *cipher = get_cipher_type(method);
    if (cipher == NULL) {
        do {
#if defined(USE_CRYPTO_MBEDTLS) && defined(USE_CRYPTO_APPLECC)
            if (supported_ciphers[method].cipher_applecc != kCCAlgorithmInvalid) {
                cipher_info.base = NULL;
                cipher_info.key_length = supported_ciphers[method].key_size * 8;
                cipher_info.iv_size = supported_ciphers[method].iv_size;
                cipher = (const cipher_kt_t *)&cipher_info;
                break;
            }
#endif
            LOGE("Cipher %s not found in crypto library",
                 supported_ciphers[method].name);
            FATAL("Cannot initialize cipher");
        } while (0);
    }
    const digest_type_t *md = get_digest_type("MD5");
    if (md == NULL) {
        FATAL("MD5 Digest not found in crypto library");
    }

    enc_key_len = bytes_to_key(cipher, md, (const uint8_t *)pass, enc_key, iv);
    if (enc_key_len == 0) {
        FATAL("Cannot generate key and IV");
    }

    enc_method = method;
    supported_ciphers[method].cipher = cipher;
    assert(enc_key_len == supported_ciphers[method].key_size);
}

int enc_init(const char *pass, const char *method)
{
    int m = TABLE;
    if (method != NULL) {
        for (m = TABLE; m < CIPHER_NUM; m++) {
            if (strcmp(method, supported_ciphers[m].name) == 0) {
                break;
            }
        }
        if (m >= CIPHER_NUM) {
            LOGE("Invalid cipher name: %s, use table instead", method);
            m = TABLE;
        }
    }
    if (m == TABLE) {
        enc_table_init(pass);
    } else {
        enc_key_init(m, pass);
    }
    return m;
}

void enc_print_all_methods(char *buf, size_t len)
{
    int m = TABLE;
    for (m = TABLE; m < CIPHER_NUM; m++) {
        const char *ciphername = supported_ciphers[m].name;
        if (ciphername
#ifdef USE_CRYPTO_MBEDTLS
                && supported_ciphers[m].cipher_mbedtls != CIPHER_UNSUPPORTED
#endif
#ifdef USE_CRYPTO_APPLECC
                && supported_ciphers[m].cipher_applecc != CCAlgorithmInvalid
#endif
           ) {
            int rc = snprintf(buf, len, (m == TABLE ? "%s" : ", %s"), ciphername);
            if (rc < 0 || rc >= len) {
                LOGE("Buffer too short");
                break;
            } else {
                buf += rc;
                len -= rc;
            }
        }
    }
}

/* --------------- AEAD --------------- */

// increment little-endian encoded unsigned integer b. Wrap around on overflow.
static void nonce_increment(uint8_t *b, size_t len) {
    int i = 0;
    for (i = 0; i < len; ++i) {
        b[i]++;
        if (b[i] != 0) {
            return;
        }
    }
}

static int
aead_cipher_encrypt(cipher_ctx_t *cipher_ctx,
uint8_t *output,
size_t *olen,
uint8_t *input,
size_t ilen,
uint8_t *ad,
size_t adlen,
uint8_t *n,
uint8_t *k)
{
    int err = CRYPTO_OK;

    size_t nlen = supported_ciphers[enc_method].iv_size;
    size_t tlen = supported_ciphers[enc_method].tag_size;

    switch (enc_method) {
    case AES_128_GCM:
    case AES_192_GCM:
    case AES_256_GCM:
#if USE_CRYPTO_OPENSSL
    case AES_128_OCB:
    case AES_192_OCB:
    case AES_256_OCB:
    case CHACHA20_IETF_POLY1305:
    {
        int len = 0;
        if (1 != EVP_CipherInit_ex(cipher_ctx->evp, NULL, NULL, NULL, n, 1))
            return CRYPTO_ERROR;

        //EVP_EncryptUpdate(cipher_ctx->evp, NULL, &len, ad, adlen);

        if (1 != EVP_EncryptUpdate(cipher_ctx->evp, output, &len, input, ilen))
            return CRYPTO_ERROR;
        *olen = len;

        /* Finalize the encryption. Normally ciphertext bytes may be written at
        * this stage, but this does not occur in GCM mode
        */
        if (1 != EVP_EncryptFinal_ex(cipher_ctx->evp, output + *olen, &len)) 
            return CRYPTO_ERROR;
        *olen += len;

        /* Get the tag */
        if (1 != EVP_CIPHER_CTX_ctrl(cipher_ctx->evp, EVP_CTRL_AEAD_GET_TAG, tlen, output + *olen))
            return CRYPTO_ERROR;
        *olen += tlen;
        err = CRYPTO_OK;
    }

#elif USE_CRYPTO_MBEDTLS
        err = mbedtls_cipher_auth_encrypt(&cipher_ctx->evp, n, nlen, ad, adlen,
            input, ilen, output, olen, output + ilen, tlen);
        *olen += tlen;
#endif
        break;
    default:
        return CRYPTO_ERROR;
    }

    return err;
}

static int
aead_cipher_decrypt(cipher_ctx_t *cipher_ctx,
uint8_t *output, size_t *olen,
uint8_t *input, size_t ilen,
uint8_t *ad, size_t adlen,
uint8_t *n, uint8_t *k)
{
    int err = CRYPTO_ERROR;

    size_t nlen = supported_ciphers[enc_method].iv_size;
    size_t tlen = supported_ciphers[enc_method].tag_size;

    switch (enc_method) {
    case AES_128_GCM:
    case AES_192_GCM:
    case AES_256_GCM:

#if USE_CRYPTO_OPENSSL
    case AES_128_OCB:
    case AES_192_OCB:
    case AES_256_OCB:
    case CHACHA20_IETF_POLY1305:
    {
        int len = 0;
        if (1 != EVP_CipherInit_ex(cipher_ctx->evp, NULL, NULL, NULL, n, 0))
            return CRYPTO_ERROR;

        /* Set the tag */
        if (1 != EVP_CIPHER_CTX_ctrl(cipher_ctx->evp, EVP_CTRL_AEAD_SET_TAG, tlen, input + ilen - tlen))
            return CRYPTO_ERROR;

        //EVP_DecryptUpdate(cipher_ctx->evp, NULL, &len, ad, adlen);

        if (1 != EVP_DecryptUpdate(cipher_ctx->evp, output, &len, input, ilen - tlen))
            return CRYPTO_ERROR;
        *olen = len;

        /* Finalize the decryption. A positive return value indicates success,
        * anything else is a failure - the plaintext is not trustworthy.
        */
        if (1 != EVP_DecryptFinal_ex(cipher_ctx->evp, output + *olen, &len))
            return CRYPTO_ERROR;
        *olen += len;
        err = CRYPTO_OK;
    }

#elif USE_CRYPTO_MBEDTLS
        err = mbedtls_cipher_auth_decrypt(&cipher_ctx->evp, n, nlen, ad, adlen,
            input, ilen - tlen, output, olen, input + ilen - tlen, tlen);
#endif
        break;
    default:
        return CRYPTO_ERROR;
    }

    return err;
}

#ifdef USE_CRYPTO_MBEDTLS
int crypto_hkdf(const mbedtls_md_info_t *md, const unsigned char *salt,
    int salt_len, const unsigned char *ikm, int ikm_len,
    const unsigned char *info, int info_len, unsigned char *okm,
    int okm_len);
#endif

#define SUBKEY_INFO "ss-subkey"

static void
aead_cipher_ctx_set_key(cipher_ctx_t *cipher_ctx, int enc)
{
#if USE_CRYPTO_OPENSSL
    size_t outlen = supported_ciphers[enc_method].key_size;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (pctx == NULL) {
        FATAL("Cannot create hkdf context");
    }

    if (EVP_PKEY_derive_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha1()) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_salt(pctx, cipher_ctx->salt, supported_ciphers[enc_method].key_size) <= 0 ||
        EVP_PKEY_CTX_set1_hkdf_key(pctx, enc_key, supported_ciphers[enc_method].key_size) <= 0 ||
        EVP_PKEY_CTX_add1_hkdf_info(pctx, SUBKEY_INFO, strlen(SUBKEY_INFO)) <= 0) {
        FATAL("Cannot setup hkdf context");
    }
    // Since the HKDF output length is variable, passing a NULL buffer as a means 
    // to obtain the requisite length is not meaningful with HKDF
    if (EVP_PKEY_derive(pctx, cipher_ctx->skey, &outlen) <= 0) {
        FATAL("Derive hkdf key failed");
    }
    assert(outlen == supported_ciphers[enc_method].key_size);

    if (!EVP_CipherInit_ex(cipher_ctx->evp, supported_ciphers[enc_method].cipher, NULL, cipher_ctx->skey, NULL, enc)) {
        FATAL("Cannot set hkdf derived key");
    }
    if (!EVP_CIPHER_CTX_ctrl(cipher_ctx->evp, EVP_CTRL_AEAD_SET_IVLEN, supported_ciphers[enc_method].iv_size, NULL)) {
        FATAL("Cannot set aead iv length");
    }
    
    EVP_PKEY_CTX_free(pctx);
#elif USE_CRYPTO_MBEDTLS
    const digest_type_t *md = mbedtls_md_info_from_string("SHA1");
    if (md == NULL) {
        FATAL("SHA1 Digest not found in crypto library");
    }

    int err = crypto_hkdf(md,
        cipher_ctx->salt, supported_ciphers[enc_method].key_size,
        enc_key, supported_ciphers[enc_method].key_size,
        (uint8_t *)SUBKEY_INFO, strlen(SUBKEY_INFO),
        cipher_ctx->skey, supported_ciphers[enc_method].key_size);
    if (err) {
        FATAL("Unable to generate subkey");
    }

    if (mbedtls_cipher_setkey(&cipher_ctx->evp, cipher_ctx->skey,
        supported_ciphers[enc_method].key_size * 8, enc) != 0) {
        FATAL("Cannot set mbed TLS cipher key");
    }
    if (mbedtls_cipher_reset(&cipher_ctx->evp) != 0) {
        FATAL("Cannot finish preparation of mbed TLS cipher context");
    }
#endif

    memset(cipher_ctx->nonce, 0, supported_ciphers[enc_method].iv_size);
    //LOGD("enc %d skey:", enc);
    //hexdump(stdout, cipher_ctx->skey, outlen);
}

static int
aead_chunk_encrypt(cipher_ctx_t *ctx, uint8_t *p, uint8_t *c,
uint8_t *n, uint16_t plen)
{
    size_t nlen = supported_ciphers[enc_method].iv_size;
    size_t tlen = supported_ciphers[enc_method].tag_size;

    assert(plen <= CHUNK_SIZE_MASK);

    int err;
    size_t clen;
    uint8_t len_buf[CHUNK_SIZE_LEN];
    uint16_t t = htons(plen & CHUNK_SIZE_MASK);
    memcpy(len_buf, &t, CHUNK_SIZE_LEN);

    clen = CHUNK_SIZE_LEN + tlen;
    err = aead_cipher_encrypt(ctx, c, &clen, len_buf, CHUNK_SIZE_LEN,
        NULL, 0, n, ctx->skey);
    if (err)
        return CRYPTO_ERROR;

    assert(clen == CHUNK_SIZE_LEN + tlen);

    nonce_increment(n, nlen);

    clen = plen + tlen;
    err = aead_cipher_encrypt(ctx, c + CHUNK_SIZE_LEN + tlen, &clen, p, plen,
        NULL, 0, n, ctx->skey);
    if (err)
        return CRYPTO_ERROR;

    assert(clen == plen + tlen);

    nonce_increment(n, nlen);

    return CRYPTO_OK;
}

/* TCP */
int
aead_encrypt(char *ciphertext, char *plaintext, ssize_t *len, struct enc_ctx *ctx)
{
    if (*len == 0) {
        return CRYPTO_OK;
    }

    int err = CRYPTO_ERROR;
    size_t salt_ofst = 0;
    size_t salt_len = enc_get_key_len();
    size_t tag_len = enc_get_tag_len();

    if (!ctx->init) {
        salt_ofst = salt_len;
    }

    // TODO: loop
    if (*len > CHUNK_SIZE_MASK) {
        *len = CHUNK_SIZE_MASK;
    }

    size_t out_len = salt_ofst + 2 * tag_len + *len + CHUNK_SIZE_LEN;

    if (!ctx->init) {
        rand_bytes(ctx->evp.salt, salt_len);
        memcpy(ciphertext, ctx->evp.salt, salt_len);
        aead_cipher_ctx_set_key(&ctx->evp, 1);
        ctx->init = 1;
    }

    err = aead_chunk_encrypt(&ctx->evp,
        (uint8_t *)plaintext,
        (uint8_t *)ciphertext + salt_ofst,
        ctx->evp.nonce, *len);
    if (err)
        return err;

    return out_len;
}

static int
aead_chunk_decrypt(cipher_ctx_t *ctx, uint8_t *p, uint8_t *c, uint8_t *n,
size_t *plen, size_t *clen)
{
    int err;
    size_t mlen;
    size_t nlen = supported_ciphers[enc_method].iv_size;
    size_t tlen = supported_ciphers[enc_method].tag_size;

    if (*clen <= 2 * tlen + CHUNK_SIZE_LEN)
        return CRYPTO_NEED_MORE;

    uint8_t len_buf[2];
    err = aead_cipher_decrypt(ctx, len_buf, plen, c, CHUNK_SIZE_LEN + tlen,
        NULL, 0, n, ctx->skey);
    if (err)
        return CRYPTO_ERROR;
    assert(*plen == CHUNK_SIZE_LEN);

    mlen = ntohs(*(uint16_t *)len_buf);
    mlen = mlen & CHUNK_SIZE_MASK;

    if (mlen == 0)
        return CRYPTO_ERROR;

    size_t chunk_len = 2 * tlen + CHUNK_SIZE_LEN + mlen;

    if (*clen < chunk_len)
        return CRYPTO_NEED_MORE;

    nonce_increment(n, nlen);

    err = aead_cipher_decrypt(ctx, p, plen, c + CHUNK_SIZE_LEN + tlen, mlen + tlen,
        NULL, 0, n, ctx->skey);
    if (err)
        return CRYPTO_ERROR;
    assert(*plen == mlen);

    nonce_increment(n, nlen);

    *clen = chunk_len;

    return CRYPTO_OK;
}

int
aead_decrypt(char *plaintext, char *ciphertext, ssize_t *len, struct enc_ctx *ctx)
{
    int err = CRYPTO_OK;
    int remain = *len;
    size_t salt_len = enc_get_key_len();

    if (!ctx->init) {
        if (*len <= salt_len)
            return 0;// CRYPTO_NEED_MORE;

        memcpy(ctx->evp.salt, ciphertext, salt_len);

        aead_cipher_ctx_set_key(&ctx->evp, 0);

        remain -= salt_len;

        ctx->init = 1;

    }

    size_t plen = 0;
    while (remain > 0) {
        size_t chunk_clen = remain;
        size_t chunk_plen = 0;
        err = aead_chunk_decrypt(&ctx->evp,
            (uint8_t *)plaintext + plen,
            (uint8_t *)ciphertext + (*len - remain),
            ctx->evp.nonce, &chunk_plen, &chunk_clen);
        if (err == CRYPTO_ERROR) {
            return err;
        }
        else if (err == CRYPTO_NEED_MORE) {
                break;
        }
        remain -= chunk_clen;
        plen += chunk_plen;
    }

    *len = *len - remain; // consumed cipher text

    return plen;
}

#ifdef USE_CRYPTO_MBEDTLS
/* HKDF-Extract(salt, IKM) -> PRK */
int crypto_hkdf_extract(const mbedtls_md_info_t *md, const unsigned char *salt,
    int salt_len, const unsigned char *ikm, int ikm_len,
    unsigned char *prk)
{
    int hash_len;
    unsigned char null_salt[MBEDTLS_MD_MAX_SIZE] = { '\0' };

    if (salt_len < 0) {
        return CRYPTO_ERROR;
    }

    hash_len = mbedtls_md_get_size(md);

    if (salt == NULL) {
        salt = null_salt;
        salt_len = hash_len;
    }

    return mbedtls_md_hmac(md, salt, salt_len, ikm, ikm_len, prk);
}

/* HKDF-Expand(PRK, info, L) -> OKM */
int crypto_hkdf_expand(const mbedtls_md_info_t *md, const unsigned char *prk,
    int prk_len, const unsigned char *info, int info_len,
    unsigned char *okm, int okm_len)
{
    int hash_len;
    int N;
    int T_len = 0, where = 0, i, ret;
    mbedtls_md_context_t ctx;
    unsigned char T[MBEDTLS_MD_MAX_SIZE];

    if (info_len < 0 || okm_len < 0 || okm == NULL) {
        return CRYPTO_ERROR;
    }

    hash_len = mbedtls_md_get_size(md);

    if (prk_len < hash_len) {
        return CRYPTO_ERROR;
    }

    if (info == NULL) {
        info = (const unsigned char *)"";
    }

    N = okm_len / hash_len;

    if ((okm_len % hash_len) != 0) {
        N++;
    }

    if (N > 255) {
        return CRYPTO_ERROR;
    }

    mbedtls_md_init(&ctx);

    if ((ret = mbedtls_md_setup(&ctx, md, 1)) != 0) {
        mbedtls_md_free(&ctx);
        return ret;
    }

    /* Section 2.3. */
    for (i = 1; i <= N; i++) {
        unsigned char c = i;

        ret = mbedtls_md_hmac_starts(&ctx, prk, prk_len) ||
            mbedtls_md_hmac_update(&ctx, T, T_len) ||
            mbedtls_md_hmac_update(&ctx, info, info_len) ||
            /* The constant concatenated to the end of each T(n) is a single
            octet. */
            mbedtls_md_hmac_update(&ctx, &c, 1) ||
            mbedtls_md_hmac_finish(&ctx, T);

        if (ret != 0) {
            mbedtls_md_free(&ctx);
            return ret;
        }

        memcpy(okm + where, T, (i != N) ? hash_len : (okm_len - where));
        where += hash_len;
        T_len = hash_len;
    }

    mbedtls_md_free(&ctx);

    return 0;
}

/* HKDF-Extract + HKDF-Expand */
int crypto_hkdf(const mbedtls_md_info_t *md, const unsigned char *salt,
    int salt_len, const unsigned char *ikm, int ikm_len,
    const unsigned char *info, int info_len, unsigned char *okm,
    int okm_len)
{
    unsigned char prk[MBEDTLS_MD_MAX_SIZE];

    return crypto_hkdf_extract(md, salt, salt_len, ikm, ikm_len, prk) ||
        crypto_hkdf_expand(md, prk, mbedtls_md_get_size(md), info, info_len,
        okm, okm_len);
}
#endif

#endif
