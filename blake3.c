#include "blake3.h"
#include <string.h>

static const uint32_t IV[8] = {
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

static const uint8_t SIGMA[7][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
    {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
    {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
    {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
    {9, 14, 11, 5, 8, 12, 15, 1, 13, 10, 0, 7, 2, 4, 6, 3},
    {11, 15, 5, 0, 1, 9, 8, 2, 14, 12, 3, 4, 7, 10, 6, 13}
};

static uint32_t load32(const void *src) {
    uint32_t w;
    memcpy(&w, src, sizeof(w));
    return w;
}

static void store32(void *dst, uint32_t w) {
    memcpy(dst, &w, sizeof(w));
}

inline static uint32_t rotate_right(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

inline static void g(uint32_t state[16], int a, int b, int c, int d, uint32_t mx, uint32_t my) {
    state[a] = state[a] + state[b] + mx;
    state[d] = rotate_right(state[d] ^ state[a], 16);
    state[c] = state[c] + state[d];
    state[b] = rotate_right(state[b] ^ state[c], 12);
    state[a] = state[a] + state[b] + my;
    state[d] = rotate_right(state[d] ^ state[a], 8);
    state[c] = state[c] + state[d];
    state[b] = rotate_right(state[b] ^ state[c], 7);
}

inline static void round_fn(uint32_t state[16], const uint32_t m[16], int r) {
    const uint8_t *s = SIGMA[r];
    g(state, 0, 4, 8, 12, m[s[0]], m[s[1]]);
    g(state, 1, 5, 9, 13, m[s[2]], m[s[3]]);
    g(state, 2, 6, 10, 14, m[s[4]], m[s[5]]);
    g(state, 3, 7, 11, 15, m[s[6]], m[s[7]]);
    g(state, 0, 5, 10, 15, m[s[8]], m[s[9]]);
    g(state, 1, 6, 11, 12, m[s[10]], m[s[11]]);
    g(state, 2, 7, 8, 13, m[s[12]], m[s[13]]);
    g(state, 3, 4, 9, 14, m[s[14]], m[s[15]]);
}

static void compress(const uint32_t cv[8], const uint32_t m[16], uint64_t t, uint32_t b, uint32_t f, uint32_t out[8]) {
    uint32_t state[16];
    memcpy(&state[0], cv, 32);
    memcpy(&state[8], IV, 16);
    state[12] = (uint32_t)t;
    state[13] = (uint32_t)(t >> 32);
    state[14] = b;
    state[15] = f;

    for (int r = 0; r < 7; r++) {
        round_fn(state, m, r);
    }

    for (int i = 0; i < 8; i++) {
        out[i] = state[i] ^ state[i + 8];
        out[i] ^= cv[i];
    }
}

typedef struct {
    uint32_t cv[8];
    uint64_t chunk_counter;
    uint8_t buf[64];
    uint8_t buf_len;
    uint32_t flags;
} blake3_hasher;

enum {
    CHUNK_START = 1 << 0,
    CHUNK_END = 1 << 1,
    PARENT = 1 << 2,
    ROOT = 1 << 3,
    KEYED_HASH = 1 << 4,
};

static void blake3_hasher_init_common(blake3_hasher *self, const uint8_t *key, uint32_t flags) {
    if (key) {
        for (int i = 0; i < 8; i++) self->cv[i] = load32(key + i * 4);
    } else {
        memcpy(self->cv, IV, 32);
    }
    self->chunk_counter = 0;
    self->buf_len = 0;
    self->flags = flags;
}

static void blake3_hasher_update(blake3_hasher *self, const uint8_t *input, size_t input_len) {
    while (input_len > 0) {
        if (self->buf_len == 64) {
            uint32_t m[16];
            for (int i = 0; i < 16; i++) m[i] = load32(self->buf + i * 4);
            uint32_t flags = self->flags;
            if (self->chunk_counter == 0) flags |= CHUNK_START;
            uint32_t out[8];
            compress(self->cv, m, self->chunk_counter, 64, flags, out);
            memcpy(self->cv, out, 32);
            self->buf_len = 0;
            self->chunk_counter++;
        }
        size_t take = 64 - self->buf_len;
        if (take > input_len) take = input_len;
        memcpy(self->buf + self->buf_len, input, take);
        self->buf_len += (uint8_t)take;
        input += take;
        input_len -= take;
    }
}

static void blake3_hasher_finalize(blake3_hasher *self, uint8_t *out, size_t out_len) {
    uint32_t m[16] = {0};
    for (int i = 0; i < 16; i++) m[i] = load32(self->buf + i * 4);
    uint32_t flags = self->flags | CHUNK_END | ROOT;
    if (self->chunk_counter == 0) flags |= CHUNK_START;
    uint32_t result[8];
    compress(self->cv, m, self->chunk_counter, self->buf_len, flags, result);
    for (int i = 0; i < 8 && i * 4 < out_len; i++) {
        store32(out + i * 4, result[i]);
    }
}

void blake3_hash(const uint8_t *input, size_t input_len, uint8_t *out, size_t out_len) {
    blake3_hasher hasher;
    blake3_hasher_init_common(&hasher, NULL, 0);
    blake3_hasher_update(&hasher, input, input_len);
    blake3_hasher_finalize(&hasher, out, out_len);
}

void blake3_keyed_hash(const uint8_t *key, const uint8_t *input, size_t input_len, uint8_t *out, size_t out_len) {
    blake3_hasher hasher;
    blake3_hasher_init_common(&hasher, key, KEYED_HASH);
    blake3_hasher_update(&hasher, input, input_len);
    blake3_hasher_finalize(&hasher, out, out_len);
}
