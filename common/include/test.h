/* test.h
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

#ifndef __TEST_H__
#define __TEST_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

/* ============= Test Result Tracking ============= */

struct test_stats {
    int total;
    int passed;
    int failed;
    int skipped;
    long total_time_us;
};

static struct test_stats _test_stats = {0};

/* ============= Color Output (optional but helpful) ============= */

#define ANSI_RED     "\x1b[31m"
#define ANSI_GREEN   "\x1b[32m"
#define ANSI_YELLOW  "\x1b[33m"
#define ANSI_BLUE    "\x1b[34m"
#define ANSI_RESET   "\x1b[0m"

#define TEST_PRINT_OK(fmt, ...) \
    printf(ANSI_GREEN "[PASS]" ANSI_RESET " " fmt "\n", ##__VA_ARGS__)

#define TEST_PRINT_FAIL(fmt, ...) \
    printf(ANSI_RED "[FAIL]" ANSI_RESET " " fmt "\n", ##__VA_ARGS__)

#define TEST_PRINT_SKIP(fmt, ...) \
    printf(ANSI_YELLOW "[SKIP]" ANSI_RESET " " fmt "\n", ##__VA_ARGS__)

#define TEST_PRINT_INFO(fmt, ...) \
    printf(ANSI_BLUE "[INFO]" ANSI_RESET " " fmt "\n", ##__VA_ARGS__)

/* ============= Assertion Macros ============= */

#define ASSERT_TRUE(cond) \
    do { \
        if (!(cond)) { \
            TEST_PRINT_FAIL("%s:%d: assertion failed: %s", \
                    __FILE__, __LINE__, #cond); \
            return 1; \
        } \
    } while (0)

#define ASSERT_FALSE(cond) \
    do { \
        if ((cond)) { \
            TEST_PRINT_FAIL("%s:%d: assertion failed (should be false): %s", \
                    __FILE__, __LINE__, #cond); \
            return 1; \
        } \
    } while (0)

#define ASSERT_EQ(a, b) \
    do { \
        if ((a) != (b)) { \
            TEST_PRINT_FAIL("%s:%d: %ld != %ld", \
                    __FILE__, __LINE__, (long)(a), (long)(b)); \
            return 1; \
        } \
    } while (0)

#define ASSERT_NE(a, b) \
    do { \
        if ((a) == (b)) { \
            TEST_PRINT_FAIL("%s:%d: %ld == %ld (should be different)", \
                    __FILE__, __LINE__, (long)(a), (long)(b)); \
            return 1; \
        } \
    } while (0)

#define ASSERT_LT(a, b) \
    do { \
        if ((a) >= (b)) { \
            TEST_PRINT_FAIL("%s:%d: %ld >= %ld", \
                    __FILE__, __LINE__, (long)(a), (long)(b)); \
            return 1; \
        } \
    } while (0)

#define ASSERT_LE(a, b) \
    do { \
        if ((a) > (b)) { \
            TEST_PRINT_FAIL("%s:%d: %ld > %ld", \
                    __FILE__, __LINE__, (long)(a), (long)(b)); \
            return 1; \
        } \
    } while (0)

#define ASSERT_GT(a, b) \
    do { \
        if ((a) <= (b)) { \
            TEST_PRINT_FAIL("%s:%d: %ld <= %ld", \
                    __FILE__, __LINE__, (long)(a), (long)(b)); \
            return 1; \
        } \
    } while (0)

#define ASSERT_GE(a, b) \
    do { \
        if ((a) < (b)) { \
            TEST_PRINT_FAIL("%s:%d: %ld < %ld", \
                    __FILE__, __LINE__, (long)(a), (long)(b)); \
            return 1; \
        } \
    } while (0)

#define ASSERT_PTR(p) \
    do { \
        if (!(p)) { \
            TEST_PRINT_FAIL("%s:%d: pointer is NULL", \
                    __FILE__, __LINE__); \
            return 1; \
        } \
    } while (0)

#define ASSERT_NULL(p) \
    do { \
        if ((p)) { \
            TEST_PRINT_FAIL("%s:%d: pointer should be NULL: %p", \
                    __FILE__, __LINE__, (p)); \
            return 1; \
        } \
    } while (0)

#define ASSERT_STR_EQ(a, b) \
    do { \
        if (strcmp((a), (b))) { \
            TEST_PRINT_FAIL("%s:%d: \"%s\" != \"%s\"", \
                    __FILE__, __LINE__, (a), (b)); \
            return 1; \
        } \
    } while (0)

#define ASSERT_STR_NE(a, b) \
    do { \
        if (!strcmp((a), (b))) { \
            TEST_PRINT_FAIL("%s:%d: \"%s\" == \"%s\" (should differ)", \
                    __FILE__, __LINE__, (a), (b)); \
            return 1; \
        } \
    } while (0)

/* ============= Test Definition & Registration ============= */

typedef int (*test_func_t)(void);

struct test_case {
    const char *name;
    test_func_t func;
};

struct test_suite {
    const char *name;
    struct test_case *cases;
    int count;
};

/* ============= Test Execution ============= */

static inline long _get_time_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static int _run_test(const char *suite_name, const char *test_name,
        test_func_t test_func)
{
    long start, end;
    int result;

    _test_stats.total++;

    start = _get_time_us();
    result = test_func();
    end = _get_time_us();

    if (result == 0) {
        TEST_PRINT_OK("%s::%s (%ldus)", suite_name, test_name,
                end - start);
        _test_stats.passed++;
    } else if (result == 2) {
        TEST_PRINT_SKIP("%s::%s", suite_name, test_name);
        _test_stats.skipped++;
    } else {
        _test_stats.failed++;
    }

    _test_stats.total_time_us += (end - start);
    return result;
}

static void run_test_suite(struct test_suite *suite)
{
    int i;

    TEST_PRINT_INFO("Running test suite: %s (%d tests)",
            suite->name, suite->count);
    printf("\n");

    for (i = 0; i < suite->count; i++) {
        _run_test(suite->name, suite->cases[i].name,
                suite->cases[i].func);
    }

    printf("\n");
}

static void print_test_summary(void)
{
    int total = _test_stats.total;
    int passed = _test_stats.passed;
    int failed = _test_stats.failed;
    int skipped = _test_stats.skipped;

    printf("\n");
    printf("====================================\n");
    printf("Test Summary:\n");
    printf("  Total:   %d\n", total);
    printf("  Passed:  " ANSI_GREEN "%d" ANSI_RESET "\n", passed);
    printf("  Failed:  " ANSI_RED "%d" ANSI_RESET "\n", failed);
    printf("  Skipped: " ANSI_YELLOW "%d" ANSI_RESET "\n", skipped);
    printf("  Time:    %.3fms\n", _test_stats.total_time_us / 1000.0);
    printf("====================================\n");

    if (failed == 0) {
        printf(ANSI_GREEN "All tests passed!" ANSI_RESET "\n");
    } else {
        printf(ANSI_RED "%d test(s) failed!" ANSI_RESET "\n", failed);
    }
    printf("\n");
}

/* ============= Helpers for Setup/Teardown ============= */

#define TEST_SKIP() return 2

/* For setup/teardown in suites */
typedef int (*setup_func_t)(void);
typedef void (*teardown_func_t)(void);

static void run_test_suite_with_hooks(struct test_suite *suite,
        setup_func_t setup,
        teardown_func_t teardown)
{
    int i;

    TEST_PRINT_INFO("Running test suite: %s (%d tests)",
            suite->name, suite->count);
    printf("\n");

    for (i = 0; i < suite->count; i++) {
        if (setup && setup() != 0) {
            TEST_PRINT_FAIL("%s::%s (setup failed)",
                    suite->name, suite->cases[i].name);
            _test_stats.total++;
            _test_stats.failed++;
            continue;
        }

        _run_test(suite->name, suite->cases[i].name,
                suite->cases[i].func);

        if (teardown)
            teardown();
    }

    printf("\n");
}

#endif /* __TEST_H__ */
