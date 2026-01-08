/* test_is.c
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
#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "test.h"
#include "is.h"

/* ============= Test Suite: is_valid_ipv4 ============= */

// Test valid IPv4 addresses
static int test_valid_ipv4_addresses(void)
{
    const char *valid_ips[] = {
        "192.168.1.100",
        "10.0.0.1",
        "172.16.254.1",
        "255.255.255.255",
        "0.0.0.0",
        "127.0.0.1",
        "8.8.8.8",
        "192.0.2.146",
        "198.51.100.0",
        "203.0.113.0",
        "169.254.0.1",
        "224.0.0.1",
        "100.64.0.1",
        "192.168.0.1",
        "10.10.10.10",
        "1.1.1.1"
    };

    int count = sizeof(valid_ips) / sizeof(valid_ips[0]);

    for (int i = 0; i < count; i++) {
        bool result = is_valid_ipv4(valid_ips[i]);
        ASSERT_TRUE(result);
    }

    return 0;
}

// Test invalid IPv4 addresses - out of range
static int test_invalid_ipv4_out_of_range(void)
{
    const char *invalid_ips[] = {
        "256.168.1.100",    // First octet > 255
        "192.256.1.100",    // Second octet > 255
        "192.168.256.100",  // Third octet > 255
        "192.168.1.256",    // Fourth octet > 255
        "300.300.300.300",  // All octets > 255
        "999.999.999.999",  // All octets > 255
        "-1.168.1.100",     // Negative number
        "192.-1.1.100",     // Negative number
        "192.168.-1.100",   // Negative number
        "192.168.1.-1"      // Negative number
    };

    int count = sizeof(invalid_ips) / sizeof(invalid_ips[0]);

    for (int i = 0; i < count; i++) {
        bool result = is_valid_ipv4(invalid_ips[i]);
        ASSERT_FALSE(result);
    }

    return 0;
}

// Test invalid IPv4 addresses - Invalid format
static int test_invalid_ipv4_format(void)
{
    const char *invalid_ips[] = {
        "192.168.1",           // Only 3 octets
        "192.168.1.100.1",     // 5 octets
        "192.168.1.",          // Ends with dot
        ".192.168.1.100",      // Starts with dot
        "192..168.1",          // Two consecutive dots
        "192.168.1.100a",      // Extra characters at end
        "a192.168.1.100",      // Extra characters at start
        "192.168.1.1a0",       // Letters inside octet
        "192,168,1,100",       // Comma separators
        "192:168:1:100",       // Colon separators
        "192.168.1.0x0A",      // Hexadecimal format
        "192.168.1. 100",      // Contains space
        "192 .168.1.100",      // Contains space
        ""                     // Empty string
    };

    int count = sizeof(invalid_ips) / sizeof(invalid_ips[0]);

    for (int i = 0; i < count; i++) {
        bool result = is_valid_ipv4(invalid_ips[i]);
        ASSERT_FALSE(result);
    }

    return 0;
}

// Test boundary values
static int test_ipv4_boundary_values(void)
{
    // Valid boundary values
    ASSERT_TRUE(is_valid_ipv4("0.0.0.0"));
    ASSERT_TRUE(is_valid_ipv4("255.255.255.255"));
    ASSERT_TRUE(is_valid_ipv4("0.255.0.255"));
    ASSERT_TRUE(is_valid_ipv4("255.0.255.0"));

    // Invalid boundary values
    ASSERT_FALSE(is_valid_ipv4("256.0.0.0"));
    ASSERT_FALSE(is_valid_ipv4("0.256.0.0"));
    ASSERT_FALSE(is_valid_ipv4("0.0.256.0"));
    ASSERT_FALSE(is_valid_ipv4("0.0.0.256"));

    return 0;
}

// Test leading zeros
static int test_ipv4_leading_zeros(void)
{
    // These should be valid (though not recommended, they are syntactically allowed)
    ASSERT_TRUE(is_valid_ipv4("192.168.001.100"));  // 001 is parsed as 1
    ASSERT_TRUE(is_valid_ipv4("010.010.010.010"));  // 010 is parsed as 10
    ASSERT_TRUE(is_valid_ipv4("000.000.000.000"));  // 000 is parsed as 0

    return 0;
}

// Test NULL pointer
static int test_ipv4_null_pointer(void)
{
    bool result = is_valid_ipv4(NULL);
    ASSERT_FALSE(result);
    return 0;
}

static struct test_case ipv4_test_cases[] = {
    {"valid_ipv4_addresses", test_valid_ipv4_addresses},
    {"invalid_ipv4_out_of_range", test_invalid_ipv4_out_of_range},
    {"invalid_ipv4_format", test_invalid_ipv4_format},
    {"ipv4_boundary_values", test_ipv4_boundary_values},
    {"ipv4_leading_zeros", test_ipv4_leading_zeros},
    {"ipv4_null_pointer", test_ipv4_null_pointer},
};

static struct test_suite ipv4_test_suite = {
    "is-ipv4",
    ipv4_test_cases,
    sizeof(ipv4_test_cases) / sizeof(ipv4_test_cases[0])
};

/* ============= Main Function ============= */

int main(void)
{
    printf("====================================\n");

    run_test_suite(&ipv4_test_suite);
    print_test_summary();

    return _test_stats.failed > 0 ? 1 : 0;
}
