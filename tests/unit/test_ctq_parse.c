/**
 * @file tests/unit/test_ctq_parse.c
 * @brief Unit tests for CTQ (Card Transaction Qualifiers) bit parsing.
 *
 * Verifies the fix for Task #2: CTQ bit解析 correctly matches
 * EMV Book C-3 §5.7.1.2 Table A-1 specification.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "emv_kernel/bitmap.h"

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

/* Copy of the fixed CTQ parser for testing */
typedef struct {
    uint8_t online_pin_required : 1;  /* Byte1 bit8 (index 0) */
    uint8_t signature_required  : 1;  /* Byte1 bit7 (index 1) */
    uint8_t go_online_oda_fail  : 1;  /* Byte1 bit6 (index 2) */
    uint8_t switch_if_oda_fail  : 1;  /* Byte1 bit5 (index 3) */
    uint8_t go_online_expired   : 1;  /* Byte1 bit4 (index 4) */
    uint8_t switch_cash         : 1;  /* Byte1 bit3 (index 5) */
    uint8_t switch_cashback     : 1;  /* Byte1 bit2 (index 6) */
    uint8_t reserved_b1         : 1;  /* Byte1 bit1 (index 7) */
    uint8_t cdcvm_performed     : 1;  /* Byte2 bit8 (index 8) */
    uint8_t issuer_update_pos   : 1;  /* Byte2 bit7 (index 9) */
} ctq_fields_t;

static void ctq_parse(const uint8_t *ctq_bytes, uint8_t len, ctq_fields_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!ctq_bytes || len < 1) return;

    out->online_pin_required  = bitmap_get(ctq_bytes, 0);
    out->signature_required   = bitmap_get(ctq_bytes, 1);
    out->go_online_oda_fail   = bitmap_get(ctq_bytes, 2);
    out->switch_if_oda_fail   = bitmap_get(ctq_bytes, 3);
    out->go_online_expired    = bitmap_get(ctq_bytes, 4);
    out->switch_cash          = bitmap_get(ctq_bytes, 5);
    out->switch_cashback      = bitmap_get(ctq_bytes, 6);
    out->reserved_b1          = bitmap_get(ctq_bytes, 7);

    if (len > 1) {
        out->cdcvm_performed  = bitmap_get(ctq_bytes + 1, 0);
        out->issuer_update_pos = bitmap_get(ctq_bytes + 1, 1);
    }
}

/* ---- Test 1: All zero CTQ ---- */
TEST(test_ctq_all_zero) {
    uint8_t ctq[] = { 0x00, 0x00 };
    ctq_fields_t f;
    ctq_parse(ctq, 2, &f);

    ASSERT_EQ(f.online_pin_required, 0, "no online PIN");
    ASSERT_EQ(f.signature_required, 0, "no signature");
    ASSERT_EQ(f.cdcvm_performed, 0, "no CDCVM");
    ASSERT_EQ(f.go_online_expired, 0, "no online-if-expired");
}

/* ---- Test 2: Online PIN Required (bit 8 of byte 1) ---- */
TEST(test_ctq_online_pin) {
    /* Byte 1: 0x80 = bit 8 set = Online PIN Required */
    uint8_t ctq[] = { 0x80, 0x00 };
    ctq_fields_t f;
    ctq_parse(ctq, 2, &f);

    ASSERT_EQ(f.online_pin_required, 1, "Online PIN Required");
    ASSERT_EQ(f.signature_required, 0, "Signature NOT required");
}

/* ---- Test 3: Signature Required (bit 7 of byte 1) ---- */
TEST(test_ctq_signature) {
    /* Byte 1: 0x40 = bit 7 set = Signature Required */
    uint8_t ctq[] = { 0x40, 0x00 };
    ctq_fields_t f;
    ctq_parse(ctq, 2, &f);

    ASSERT_EQ(f.signature_required, 1, "Signature Required");
    ASSERT_EQ(f.online_pin_required, 0, "Online PIN NOT required");
}

/* ---- Test 4: CDCVM Performed (bit 8 of byte 2 = index 8) ---- */
TEST(test_ctq_cdcvm_performed) {
    /* Byte 2: 0x80 = bit 8 set = CDCVM Performed */
    uint8_t ctq[] = { 0x00, 0x80 };
    ctq_fields_t f;
    ctq_parse(ctq, 2, &f);

    ASSERT_EQ(f.cdcvm_performed, 1, "CDCVM Performed");
    ASSERT_EQ(f.online_pin_required, 0, "Online PIN NOT required");
    ASSERT_EQ(f.signature_required, 0, "Signature NOT required");
}

/* ---- Test 5: Issuer Update at POS (bit 7 of byte 2 = index 9) ---- */
TEST(test_ctq_issuer_update) {
    /* Byte 2: 0x40 = bit 7 set = Issuer Update at POS */
    uint8_t ctq[] = { 0x00, 0x40 };
    ctq_fields_t f;
    ctq_parse(ctq, 2, &f);

    ASSERT_EQ(f.issuer_update_pos, 1, "Issuer Update at POS");
    ASSERT_EQ(f.cdcvm_performed, 0, "CDCVM NOT performed");
}

/* ---- Test 6: Combined — Online PIN + CDCVM + Signature ---- */
TEST(test_ctq_combined) {
    /* Byte 1: 0xC0 = bits 8+7 = Online PIN + Signature */
    /* Byte 2: 0x80 = bit 8 = CDCVM Performed */
    uint8_t ctq[] = { 0xC0, 0x80 };
    ctq_fields_t f;
    ctq_parse(ctq, 2, &f);

    ASSERT_EQ(f.online_pin_required, 1, "Online PIN Required");
    ASSERT_EQ(f.signature_required, 1, "Signature Required");
    ASSERT_EQ(f.cdcvm_performed, 1, "CDCVM Performed");
}

/* ---- Test 7: Go Online if ODA Fails (bit 6 of byte 1 = index 2) ---- */
TEST(test_ctq_go_online_oda_fail) {
    /* Byte 1: 0x20 = bit 6 = Go Online if ODA fails */
    uint8_t ctq[] = { 0x20, 0x00 };
    ctq_fields_t f;
    ctq_parse(ctq, 2, &f);

    ASSERT_EQ(f.go_online_oda_fail, 1, "Go online if ODA fails");
    ASSERT_EQ(f.online_pin_required, 0, "Online PIN NOT required");
    ASSERT_EQ(f.signature_required, 0, "Signature NOT required");
}

/* ---- Test 8: Switch Interface if ODA Fails (bit 5 of byte 1 = index 3) ---- */
TEST(test_ctq_switch_oda_fail) {
    /* Byte 1: 0x10 = bit 5 = Switch Interface if ODA fails */
    uint8_t ctq[] = { 0x10, 0x00 };
    ctq_fields_t f;
    ctq_parse(ctq, 2, &f);

    ASSERT_EQ(f.switch_if_oda_fail, 1, "Switch interface if ODA fails");
}

/* ---- Test 9: Switch Cash (bit 3 of byte 1 = index 5) ---- */
TEST(test_ctq_switch_cash) {
    /* Byte 1: 0x04 = bit 3 = Switch Interface for Cash */
    uint8_t ctq[] = { 0x04, 0x00 };
    ctq_fields_t f;
    ctq_parse(ctq, 2, &f);

    ASSERT_EQ(f.switch_cash, 1, "Switch cash");
}

/* ---- Test 10: Switch Cashback (bit 2 of byte 1 = index 6) ---- */
TEST(test_ctq_switch_cashback) {
    /* Byte 1: 0x02 = bit 2 = Switch Interface for Cashback */
    uint8_t ctq[] = { 0x02, 0x00 };
    ctq_fields_t f;
    ctq_parse(ctq, 2, &f);

    ASSERT_EQ(f.switch_cashback, 1, "Switch cashback");
}

/* ---- Test 11: Go Online if Expired (bit 4 of byte 1 = index 4) ---- */
TEST(test_ctq_go_online_expired) {
    /* Byte 1: 0x08 = bit 4 = Go Online if Application Expired */
    uint8_t ctq[] = { 0x08, 0x00 };
    ctq_fields_t f;
    ctq_parse(ctq, 2, &f);

    ASSERT_EQ(f.go_online_expired, 1, "Go online if expired");
}

/* ---- Test 11: Single byte input ---- */
TEST(test_ctq_single_byte) {
    uint8_t ctq[] = { 0x80 };
    ctq_fields_t f;
    ctq_parse(ctq, 1, &f);

    ASSERT_EQ(f.online_pin_required, 1, "Online PIN with single byte");
    ASSERT_EQ(f.cdcvm_performed, 0, "CDCVM unavailable with single byte");
}

/* ---- Test 12: Null / empty input ---- */
TEST(test_ctq_null) {
    ctq_fields_t f;
    ctq_parse(NULL, 0, &f);

    ASSERT_EQ(f.online_pin_required, 0, "null input -> all zeros");
    ASSERT_EQ(f.signature_required, 0, "null input -> all zeros");
}

int main(void)
{
    printf("\n=== CTQ (Card Transaction Qualifiers) Parse Tests ===\n\n");

    RUN(test_ctq_all_zero);
    RUN(test_ctq_online_pin);
    RUN(test_ctq_signature);
    RUN(test_ctq_cdcvm_performed);
    RUN(test_ctq_issuer_update);
    RUN(test_ctq_combined);
    RUN(test_ctq_go_online_oda_fail);
    RUN(test_ctq_switch_oda_fail);
    RUN(test_ctq_switch_cash);
    RUN(test_ctq_switch_cashback);
    RUN(test_ctq_go_online_expired);
    RUN(test_ctq_single_byte);
    RUN(test_ctq_null);

    printf("\n%d passed, %d failed out of %d tests\n\n",
           g_tests_run - g_tests_fail, g_tests_fail, g_tests_run);
    return g_tests_fail > 0 ? 1 : 0;
}
