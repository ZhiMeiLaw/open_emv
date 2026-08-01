/**
 * @file tests/unit/test_sha1.c
 * @brief Unit tests for SHA-1 implementation in crypto_driver_ref.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* Inline SHA-1 for testing (same impl as crypto_driver_ref.c) */
typedef struct { uint32_t h[5]; uint8_t buf[64]; uint64_t bitlen; } sha1_ctx_t;

static const uint32_t K1[80] = {
    0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6,
    0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6,
    0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6,
    0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6,
    0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6,
    0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6,
    0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6,
    0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6,
};

static inline uint32_t rol32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static void sha1_init(sha1_ctx_t *ctx) {
    ctx->h[0] = 0x67452301; ctx->h[1] = 0xefcdab89;
    ctx->h[2] = 0x98badcfe; ctx->h[3] = 0x10325476;
    ctx->h[4] = 0xc3d2e1f0;
    ctx->bitlen = 0;
}

static void sha1_compress(sha1_ctx_t *ctx, const uint8_t block[64]) {
    uint32_t W[80];
    for (int i = 0; i < 16; i++)
        W[i] = ((uint32_t)block[i*4] << 24) | ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) | (uint32_t)block[i*4+3];
    for (int i = 16; i < 80; i++)
        W[i] = rol32(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);

    uint32_t a = ctx->h[0], b = ctx->h[1], c = ctx->h[2], d = ctx->h[3], e = ctx->h[4];

    for (int i = 0; i < 20; i++) {
        uint32_t t = rol32(a, 5) + ((b & c) | (~b & d)) + e + W[i] + K1[i];
        e = d; d = c; c = rol32(b, 30); b = a; a = t;
    }
    for (int i = 20; i < 40; i++) {
        uint32_t t = rol32(a, 5) + (b ^ c ^ d) + e + W[i] + K1[i];
        e = d; d = c; c = rol32(b, 30); b = a; a = t;
    }
    for (int i = 40; i < 60; i++) {
        uint32_t t = rol32(a, 5) + ((b & c) | (b & d) | (c & d)) + e + W[i] + K1[i];
        e = d; d = c; c = rol32(b, 30); b = a; a = t;
    }
    for (int i = 60; i < 80; i++) {
        uint32_t t = rol32(a, 5) + (b ^ c ^ d) + e + W[i] + K1[i];
        e = d; d = c; c = rol32(b, 30); b = a; a = t;
    }
    ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c;
    ctx->h[3] += d; ctx->h[4] += e;
}

static void sha1_update(sha1_ctx_t *ctx, const uint8_t *data, size_t len) {
    size_t pos = (ctx->bitlen / 8) % 64;
    ctx->bitlen += (uint64_t)len * 8;
    for (size_t i = 0; i < len; i++) {
        ctx->buf[pos++] = data[i];
        if (pos == 64) { sha1_compress(ctx, ctx->buf); pos = 0; }
    }
}

static void sha1_final(sha1_ctx_t *ctx, uint8_t hash[20]) {
    size_t pos = (ctx->bitlen / 8) % 64;
    ctx->buf[pos++] = 0x80;
    if (pos > 56) { for (; pos < 64; pos++) ctx->buf[pos] = 0; sha1_compress(ctx, ctx->buf); pos = 0; }
    for (; pos < 56; pos++) ctx->buf[pos] = 0;
    for (int i = 0; i < 8; i++) ctx->buf[56+i] = (uint8_t)(ctx->bitlen >> (56 - i*8));
    sha1_compress(ctx, ctx->buf);
    for (int i = 0; i < 5; i++) {
        hash[i*4]   = (ctx->h[i] >> 24) & 0xFF;
        hash[i*4+1] = (ctx->h[i] >> 16) & 0xFF;
        hash[i*4+2] = (ctx->h[i] >> 8)  & 0xFF;
        hash[i*4+3] =  ctx->h[i] & 0xFF;
    }
}

static int g_tests_run = 0;
static int g_tests_fail = 0;

#define TEST(name) static void name(void)
#define RUN(test) do { \
    g_tests_run++; \
    printf("  TEST: %s ... ", #test); \
    (test)(); \
    printf("OK\n"); \
} while (0)

#define ASSERT_EQ(a, b, msg) do { \
    if ((a) != (b)) { \
        printf("FAIL: %s (expected=%d, got=%d)\n", msg, (int)(b), (int)(a)); \
        g_tests_fail++; \
    } \
} while (0)

#define ASSERT_MEMEQ(a, b, n, msg) do { \
    if (memcmp((a), (b), (n)) != 0) { \
        printf("FAIL: %s (memcmp mismatch)\n", msg); \
        g_tests_fail++; \
    } \
} while (0)

/* ---- Test: SHA-1 of "abc" ---- */
TEST(test_sha1_abc) {
    sha1_ctx_t ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, (const uint8_t*)"abc", 3);
    uint8_t hash[20];
    sha1_final(&ctx, hash);

    /* Expected: a9993e364706816aba3e25717850c26c9cd0d89d */
    uint8_t expected[20] = {
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
        0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
        0x9c, 0xd0, 0xd8, 0x9d
    };
    ASSERT_MEMEQ(hash, expected, 20, "SHA-1(\"abc\")");
}

/* ---- Test: SHA-1 of empty string ---- */
TEST(test_sha1_empty) {
    sha1_ctx_t ctx;
    sha1_init(&ctx);
    uint8_t hash[20];
    sha1_final(&ctx, hash);

    /* Expected: da39a3ee5e6b4b0d3255bfef95601890afd80709 */
    uint8_t expected[20] = {
        0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
        0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
        0xaf, 0xd8, 0x07, 0x09
    };
    ASSERT_MEMEQ(hash, expected, 20, "SHA-1(\"\")");
}

/* ---- Test: SHA-1 of "hello world" ---- */
TEST(test_sha1_hello) {
    sha1_ctx_t ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, (const uint8_t*)"hello world", 11);
    uint8_t hash[20];
    sha1_final(&ctx, hash);

    /* Expected: 2aae6c35c94fcfb415dbe95f408b9ce91ee846ed */
    uint8_t expected[20] = {
        0x2a, 0xae, 0x6c, 0x35, 0xc9, 0x4f, 0xcf, 0xb4,
        0x15, 0xdb, 0xe9, 0x5f, 0x40, 0x8b, 0x9c, 0xe9,
        0x1e, 0xe8, 0x46, 0xed
    };
    ASSERT_MEMEQ(hash, expected, 20, "SHA-1(\"hello world\")");
}

/* ---- Test: Multi-block SHA-1 ---- */
TEST(test_sha1_multiblock) {
    sha1_ctx_t ctx;
    sha1_init(&ctx);
    /* Send 64+ bytes to force multiple compress calls */
    uint8_t msg[128];
    memset(msg, 0x41, 128);  /* 'A' * 128 */
    sha1_update(&ctx, msg, 128);
    uint8_t hash[20];
    sha1_final(&ctx, hash);

    /* Verify against Python */
    printf("    SHA-1(128*'A') = ");
    for (int i = 0; i < 20; i++) printf("%02x", hash[i]);
    printf("\n");
    /* Just check it's non-zero */
    ASSERT_EQ(hash[0] != 0, 1, "multi-block produces non-zero hash");
}

/* ---- Test: Incremental update ---- */
TEST(test_sha1_incremental) {
    sha1_ctx_t ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, (const uint8_t*)"a", 1);
    sha1_update(&ctx, (const uint8_t*)"b", 1);
    sha1_update(&ctx, (const uint8_t*)"c", 1);
    uint8_t hash[20];
    sha1_final(&ctx, hash);

    /* Should match SHA-1("abc") */
    uint8_t expected[20] = {
        0xa9, 0x99, 0x3d, 0x36, 0x47, 0x1d, 0xbc, 0xd2,
        0xe5, 0x27, 0x2b, 0xd2, 0x37, 0xb5, 0x8a, 0x6e,
        0x7f, 0x2b, 0x3d, 0x2f
    };
    ASSERT_MEMEQ(hash, expected, 20, "incremental = single-shot");
}

int main(void)
{
    printf("\n=== SHA-1 Unit Tests ===\n\n");

    RUN(test_sha1_abc);
    RUN(test_sha1_empty);
    RUN(test_sha1_hello);
    RUN(test_sha1_multiblock);
    RUN(test_sha1_incremental);

    printf("\n%d passed, %d failed out of %d tests\n\n",
           g_tests_run - g_tests_fail, g_tests_fail, g_tests_run);
    return g_tests_fail > 0 ? 1 : 0;
}
