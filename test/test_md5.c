/* test_md5.c
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
#include "md5.h"

// Test content for temporary files
static const char *test_content = "Hello, World! This is a test file for MD5 hashing.\n";

static int calculate_file_md5(const char *filename, char *md5_str)
{
    FILE *file = fopen(filename, "rb");
    if (!file) {
        return -1;
    }

    md5_ctx_t context;
    unsigned char buffer[1024];
    unsigned char digest[16];
    size_t bytes;
    int i;

    md5_init(&context);

    while ((bytes = fread(buffer, 1, 1024, file)) != 0) {
        md5_update(&context, buffer, bytes);
    }

    md5_final(digest, &context);
    fclose(file);

    // Convert MD5 digest to hexadecimal string
    for (i = 0; i < 16; i++) {
        sprintf(md5_str + (i * 2), "%02x", digest[i]);
    }
    md5_str[32] = '\0';

    return 0;
}

// Create a temporary test file
static int create_test_file(const char *filename, const char *content)
{
    FILE *file = fopen(filename, "w");
    if (!file) {
        return -1;
    }
    fputs(content, file);
    fclose(file);
    return 0;
}

// Delete temporary file
static void remove_test_file(const char *filename)
{
    unlink(filename);
}

// Retrieve file MD5 using system's md5sum command
static int get_system_md5(const char *filename, char *md5_output, size_t output_size)
{
    char command[256];
    FILE *pipe;

    snprintf(command, sizeof(command), "md5sum '%s' | cut -d' ' -f1", filename);

    pipe = popen(command, "r");
    if (!pipe) {
        return -1;
    }

    if (fgets(md5_output, output_size, pipe) == NULL) {
        pclose(pipe);
        return -1;
    }

    // Remove newline character
    size_t len = strlen(md5_output);
    if (len > 0 && md5_output[len-1] == '\n') {
        md5_output[len-1] = '\0';
    }

    pclose(pipe);
    return 0;
}

/* ============= Test Cases ============= */

// Test empty file
static int test_md5_empty_file(void)
{
    const char *filename = "test_empty.txt";
    char our_md5[40];
    char system_md5[40];

    // Create empty file
    FILE *file = fopen(filename, "w");
    if (!file) {
        TEST_PRINT_FAIL("Failed to create empty test file");
        return 1;
    }
    fclose(file);

    // Compute our MD5
    if (calculate_file_md5(filename, our_md5) != 0) {
        remove_test_file(filename);
        TEST_PRINT_FAIL("Failed to calculate MD5 for empty file");
        return 1;
    }

    // Get system MD5
    if (get_system_md5(filename, system_md5, sizeof(system_md5)) != 0) {
        remove_test_file(filename);
        TEST_PRINT_FAIL("Failed to get system MD5 for empty file");
        return 1;
    }

    remove_test_file(filename);

    // Compare results
    ASSERT_STR_EQ(our_md5, system_md5);

    TEST_PRINT_INFO("Empty file MD5: %s", our_md5);
    return 0;
}

// Test small file
static int test_md5_small_file(void)
{
    const char *filename = "test_small.txt";
    char our_md5[40];
    char system_md5[40];

    // Create test file
    if (create_test_file(filename, test_content) != 0) {
        TEST_PRINT_FAIL("Failed to create small test file");
        return 1;
    }

    // Compute our MD5
    if (calculate_file_md5(filename, our_md5) != 0) {
        remove_test_file(filename);
        TEST_PRINT_FAIL("Failed to calculate MD5 for small file");
        return 1;
    }

    // Get system MD5
    if (get_system_md5(filename, system_md5, sizeof(system_md5)) != 0) {
        remove_test_file(filename);
        TEST_PRINT_FAIL("Failed to get system MD5 for small file");
        return 1;
    }

    remove_test_file(filename);

    // Compare results
    ASSERT_STR_EQ(our_md5, system_md5);

    TEST_PRINT_INFO("Small file MD5: %s", our_md5);
    return 0;
}

// Test large file (1MB)
static int test_md5_large_file(void)
{
    const char *filename = "test_large.txt";
    char our_md5[40];
    char system_md5[40];
    FILE *file;
    int i;

    // Create 1MB large file
    file = fopen(filename, "w");
    if (!file) {
        TEST_PRINT_FAIL("Failed to create large test file");
        return 1;
    }

    // Write repeated pattern data
    for (i = 0; i < 1024 * 1024; i++) {
        fputc(i % 256, file);
    }
    fclose(file);

    // Compute our MD5
    if (calculate_file_md5(filename, our_md5) != 0) {
        remove_test_file(filename);
        TEST_PRINT_FAIL("Failed to calculate MD5 for large file");
        return 1;
    }

    // Get system MD5
    if (get_system_md5(filename, system_md5, sizeof(system_md5)) != 0) {
        remove_test_file(filename);
        TEST_PRINT_FAIL("Failed to get system MD5 for large file");
        return 1;
    }

    remove_test_file(filename);

    // Compare results
    ASSERT_STR_EQ(our_md5, system_md5);

    TEST_PRINT_INFO("Large file MD5: %s", our_md5);
    return 0;
}

// Test non-existent file case
static int test_md5_nonexistent_file(void)
{
    const char *filename = "nonexistent_file_12345.txt";
    char md5[40];

    // Attempt to compute MD5 for a non-existent file
    int result = calculate_file_md5(filename, md5);

    // Should return an error
    ASSERT_NE(result, 0);

    return 0;
}

// Test MD5 values for known strings
static int test_known_md5_values(void)
{
    const char *test_cases[][2] = {
        {"", "d41d8cd98f00b204e9800998ecf8427e"},  // empty string
        {"abc", "900150983cd24fb0d6963f7d28e17f72"},  // "abc"
        {"hello world", "5eb63bbbe01eeed093cb22bb8f5acdc3"},  // "hello world"
    };

    char filename[64] = { 0 };
    int fd;
    char our_md5[40];
    unsigned long i;

    for (i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
        memset(filename, 0, sizeof(filename));
        snprintf(filename, sizeof(filename), "/tmp/test_known_%ld_XXXXXX", i);

        // Create temporary file
        fd = mkstemp(filename);
        if (fd == -1) {
            TEST_PRINT_FAIL("Failed to create temporary file");
            return 1;
        }

        // Write test data
        write(fd, test_cases[i][0], strlen(test_cases[i][0]));
        close(fd);

        // Compute our MD5
        if (calculate_file_md5(filename, our_md5) != 0) {
            remove_test_file(filename);
            TEST_PRINT_FAIL("Failed to calculate MD5 for known value test");
            return 1;
        }

        // Verify MD5 value
        ASSERT_STR_EQ(our_md5, test_cases[i][1]);

        remove_test_file(filename);
    }

    return 0;
}

/* ============= Test Suite Definition ============= */

static struct test_case md5_test_cases[] = {
    {"empty_file", test_md5_empty_file},
    {"small_file", test_md5_small_file},
    {"large_file", test_md5_large_file},
    {"nonexistent_file", test_md5_nonexistent_file},
    {"known_md5_values", test_known_md5_values},
};

static struct test_suite md5_test_suite = {
    .name = "md5",
    .cases = md5_test_cases,
    .count = sizeof(md5_test_cases) / sizeof(md5_test_cases[0])
};

/* ============= Main Function ============= */

int main(void)
{
    printf("====================================\n");
    run_test_suite(&md5_test_suite);
    print_test_summary();

    return _test_stats.failed > 0 ? 1 : 0;
}
