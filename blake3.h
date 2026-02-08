#ifndef BLAKE3_H
#define BLAKE3_H

#include <stddef.h>
#include <stdint.h>

#define BLAKE3_KEY_LEN 32
#define BLAKE3_OUT_LEN 32
#define BLAKE3_BLOCK_LEN 64
#define BLAKE3_CHUNK_LEN 1024

void blake3_hash(const uint8_t *input, size_t input_len, uint8_t *out, size_t out_len);
void blake3_keyed_hash(const uint8_t *key, const uint8_t *input, size_t input_len, uint8_t *out, size_t out_len);

#endif
