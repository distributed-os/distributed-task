/* test_crc.c
 *
 * Copyright (C) 2025 Ray Lee
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>

#include "test.h"
#include "crc.h"

// ref https://crccalc.com

/* Test 1: Empty data */
static int test_crc16_empty(void)
{
    uint16_t result = crc16(0x0000, NULL, 0);
    // CRC for empty data is typically the initial value
    ASSERT_EQ(result, 0x0000);
    return 0;
}

/* Test 2: Single byte */
static int test_crc16_single_byte(void)
{
    uint8_t data1[] = {0x01};
    uint8_t data2[] = {'a'};
    uint16_t result;

    result = crc16(0x0000, data1, sizeof(data1));
    ASSERT_EQ(result, 0xC0C1);

    result = crc16(0x0000, data2, sizeof(data2));
    ASSERT_EQ(result, 0xE8C1);

    return 0;
}

/* Test 3: Basic string test */
static int test_crc16_basic_string(void)
{
    const char *test_str = "abc";
    uint16_t result = crc16(0x0000, (const uint8_t*)test_str, strlen(test_str));

    uint16_t expected_crc = 0x9738;

    TEST_PRINT_INFO("CRC16 of 'abc' = 0x%04X", result);
    ASSERT_EQ(result, expected_crc);

    return 0;
}

/* Test 4: Multiple chunks */
static int test_crc16_multiple_chunks(void)
{
    const char *chunk1 = "Hello ";
    const char *chunk2 = "World";
    const char *full = "Hello World";

    // Compute CRC for the entire string at once
    uint16_t full_crc = crc16(0x0000, (const uint8_t*)full, strlen(full));

    // Compute CRC in chunks
    uint16_t chunked_crc = crc16(0x0000, (const uint8_t*)chunk1, strlen(chunk1));
    chunked_crc = crc16(chunked_crc, (const uint8_t*)chunk2, strlen(chunk2));

    // Both methods should yield the same result
    ASSERT_EQ(full_crc, chunked_crc);

    return 0;
}

/* Test 5: All zeros data */
static int test_crc16_all_zeros(void)
{
    uint8_t zeros[8] = {0};
    uint16_t result = crc16(0x0000, zeros, sizeof(zeros));

    // CRC of all-zero data is typically 0
    TEST_PRINT_INFO("CRC16 of 8 zeros = 0x%04X", result);
    ASSERT_EQ(result, 0x0000);

    return 0;
}

/* Test 6: All ones data */
static int test_crc16_all_ones(void)
{
    uint8_t ones[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint16_t result = crc16(0x0000, ones, sizeof(ones));

    TEST_PRINT_INFO("CRC16 of 8 ones = 0x%04X", result);

    uint16_t expected_crc = 0x8441;
    ASSERT_EQ(result, expected_crc);

    return 0;
}

/* Test 7: Different initial values */
static int test_crc16_different_initial(void)
{
    const char *test_str = "test";

    uint16_t crc1 = crc16(0x0000, (const uint8_t*)test_str, strlen(test_str));
    uint16_t crc2 = crc16(0xFFFF, (const uint8_t*)test_str, strlen(test_str));

    // Different initial values should produce different results
    ASSERT_NE(crc1, crc2);

    return 0;
}

/* Test 8: Known test vectors for different CRC16 variants */
static int test_crc16_known_vector(void)
{
    const char *test_data = "123456789";

    // Expected CRC for string "123456789"
    uint16_t expected_crc = 0xBB3D;

    uint16_t result = crc16(0x0000, (const uint8_t*)test_data, strlen(test_data));

    TEST_PRINT_INFO("Known vector test: got 0x%04X, expected 0x%04X", result, expected_crc);

    ASSERT_EQ(result, expected_crc);

    return 0;
}

/* ============= Test Suite Definition ============= */

static struct test_case crc16_test_cases[] = {
    {"empty_data", test_crc16_empty},
    {"single_byte", test_crc16_single_byte},
    {"basic_string", test_crc16_basic_string},
    {"multiple_chunks", test_crc16_multiple_chunks},
    {"all_zeros", test_crc16_all_zeros},
    {"all_ones", test_crc16_all_ones},
    {"different_initial", test_crc16_different_initial},
    {"known_vector", test_crc16_known_vector},
};

static struct test_suite crc16_test_suite = {
    "crc",
    crc16_test_cases,
    sizeof(crc16_test_cases) / sizeof(crc16_test_cases[0])
};

/* ============= Main Function ============= */

int main(void)
{
    printf("====================================\n");

    run_test_suite(&crc16_test_suite);
    print_test_summary();

    return _test_stats.failed > 0 ? 1 : 0;
}
