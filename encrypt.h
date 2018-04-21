/*
 * encrypt.h - Define the enryptor's interface
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

#ifndef _ENCRYPT_H
#define _ENCRYPT_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef _WIN32
#include <sys/socket.h>
#else
#include <Winsock2.h>  // ntoh hton

#ifdef max
#undef max
#endif

#ifdef min
#undef min
#endif

#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#ifdef _MSC_VER
#define ssize_t int
#endif


#if defined(USE_CRYPTO_OPENSSL)

#include <openssl/evp.h>
typedef EVP_CIPHER cipher_kt_t;
typedef EVP_CIPHER_CTX cipher_evp_t;
typedef EVP_MD digest_type_t;
#define MAX_KEY_LENGTH EVP_MAX_KEY_LENGTH
#define MAX_IV_LENGTH EVP_MAX_IV_LENGTH
#define MAX_MD_SIZE EVP_MAX_MD_SIZE

#elif defined(USE_CRYPTO_MBEDTLS)

#include <mbedtls/cipher.h>
#include <mbedtls/md.h>
typedef mbedtls_cipher_info_t cipher_kt_t;
typedef mbedtls_cipher_context_t cipher_evp_t;
typedef mbedtls_md_info_t digest_type_t;
#define MAX_KEY_LENGTH 64
#define MAX_IV_LENGTH MBEDTLS_MAX_IV_LENGTH
#define MAX_MD_SIZE MBEDTLS_MD_MAX_SIZE

#endif

#define MAX_NONCE_LENGTH MAX_IV_LENGTH  // 32???
#define MAX_TAG_LENGTH          16
#define CHUNK_SIZE_LEN          2
#define CHUNK_SIZE_MASK         0x3FFF

#define ADDRTYPE_MASK 0xF

#define CRYPTO_ERROR     -2
#define CRYPTO_NEED_MORE -1
#define CRYPTO_OK         0



#ifdef USE_CRYPTO_APPLECC

#include <CommonCrypto/CommonCrypto.h>

#define kCCAlgorithmInvalid UINT32_MAX
#define kCCContextValid 0
#define kCCContextInvalid -1

typedef struct {
    CCCryptorRef cryptor;
    int valid;
    CCOperation encrypt;
    CCAlgorithm cipher;
    CCMode mode;
    CCPadding padding;
    uint8_t iv[MAX_IV_LENGTH];
    uint8_t key[MAX_KEY_LENGTH];
    size_t iv_len;
    size_t key_len;
} cipher_cc_t;

#endif

typedef struct {
#if defined(USE_CRYPTO_OPENSSL)
    cipher_evp_t *evp;
#else
    cipher_evp_t evp;
#endif
#ifdef USE_CRYPTO_APPLECC
    cipher_cc_t cc;
#endif
    uint8_t salt[MAX_KEY_LENGTH]; // first rand bytes of TCP stream, used by HKDF
    uint8_t skey[MAX_KEY_LENGTH]; // HKDF derived AEAD key
    uint8_t nonce[MAX_NONCE_LENGTH]; // AEAD iv, increment every operation
} cipher_ctx_t;

#define BLOCK_SIZE 32

#define NONE                -1
enum{
    TABLE = 0,
    RC4,
    RC4_MD5,
    AES_128_CFB,
    AES_192_CFB,
    AES_256_CFB,
    BF_CFB,
    CAMELLIA_128_CFB,
    CAMELLIA_192_CFB,
    CAMELLIA_256_CFB,
    CAST5_CFB,
    DES_CFB,
    IDEA_CFB,
    RC2_CFB,
    SEED_CFB,
    AES_128_OFB,
    AES_192_OFB,
    AES_256_OFB,
    AES_128_CTR,
    AES_192_CTR,
    AES_256_CTR,
    AES_128_CFB8,
    AES_192_CFB8,
    AES_256_CFB8,
    AES_128_CFB1,
    AES_192_CFB1,
    AES_256_CFB1,
    CHACHA20,
    AES_128_GCM,
    AES_192_GCM,
    AES_256_GCM,
    AES_128_OCB,
    AES_192_OCB,
    AES_256_OCB,
    CHACHA20_IETF_POLY1305,
    CIPHER_NUM,      /* must be last */
};


#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

struct enc_ctx {
    unsigned int init:1;
    unsigned int aead:1;
    cipher_ctx_t evp;
};

char * ss_encrypt_all(int buf_size, char *plaintext, ssize_t *len, int method);
char * ss_decrypt_all(int buf_size, char *ciphertext, ssize_t *len, int method);
char * ss_encrypt(char *ciphertext, char *plaintext, ssize_t *len,
                  struct enc_ctx *ctx);
char * ss_decrypt(char *plaintext, char *ciphertext, ssize_t *len,
                  struct enc_ctx *ctx);
int aead_encrypt(char *ciphertext, char *plaintext, ssize_t *len, struct enc_ctx *ctx);
int aead_decrypt(char *plaintext, char *ciphertext, ssize_t *len, struct enc_ctx *ctx);

void enc_ctx_init(int method, struct enc_ctx *ctx, int enc);
int enc_init(const char *pass, const char *method);
int enc_get_iv_len(void);
void cipher_context_release(cipher_ctx_t *evp);
unsigned char *enc_md5(const unsigned char *d, size_t n, unsigned char *md);
void enc_print_all_methods(char *buf, size_t len);

#endif // _ENCRYPT_H
