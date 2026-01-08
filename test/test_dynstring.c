#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "test.h"
#include "dynstring.h"

/* ================= Test Case Definitions ================= */
static int test_string_new(void)
{
    string_t *s = string_new();
    ASSERT_PTR(s);
    ASSERT_EQ(string_len(s), 0);
    ASSERT_EQ(string_cap(s), 0);
    ASSERT_STR_EQ(string_as_str(s), "");
    string_drop(s);
    return 0;
}

static int test_string_from(void)
{
    const char *literal = "Hello";
    string_t *s = string_from(literal);
    ASSERT_PTR(s);
    ASSERT_EQ(string_len(s), 5);
    ASSERT_EQ(string_cap(s), 5);
    ASSERT_STR_EQ(string_as_str(s), "Hello");
    string_drop(s);
    return 0;
}

static int test_string_push_char(void)
{
    string_t *s = string_new();
    string_push(s, 'H');
    string_push(s, 'i');
    ASSERT_EQ(string_len(s), 2);

    ASSERT_STR_EQ(string_as_str(s), "Hi");
    string_drop(s);
    return 0;
}

static int test_string_push_str(void)
{
    string_t *s = string_new();
    string_push(s, 'R');
    string_push_str(s, "ust");
    string_push_str(s, " is ");
    string_push_str(s, "safe!");
    ASSERT_STR_EQ(string_as_str(s), "Rust is safe!");
    ASSERT_EQ(string_len(s), 13);
    string_drop(s);
    return 0;
}

static int test_capacity_growth(void)
{
    string_t *s = string_new();
    ASSERT_EQ(string_cap(s), 0);
    // push: 0 -> 4
    string_push(s, 'a');
    ASSERT_EQ(string_cap(s), 4);
    ASSERT_EQ(string_len(s), 1);

    string_push(s, 'b');
    string_push(s, 'c');
    ASSERT_EQ(string_len(s), 3);
    ASSERT_EQ(string_cap(s), 4);

    //  if (len + 1 >= cap) -> 8
    string_push(s, 'd');
    ASSERT_EQ(string_len(s), 4);
    ASSERT_EQ(string_cap(s), 8);
    string_drop(s);
    return 0;
}

static int test_concatenation(void)
{
    string_t *s1 = string_from("Hello");
    string_t *s2 = string_from("World");

    string_push_str(s1, " ");
    string_push_str(s1, string_as_str(s2));
    ASSERT_STR_EQ(string_as_str(s1), "Hello World");

    // not move
    ASSERT_STR_EQ(string_as_str(s2), "World");
    string_drop(s1);
    string_drop(s2);
    return 0;
}

static int test_null_safety(void)
{
    string_t *s = string_from("Base");

    string_push_str(s, NULL);
    ASSERT_STR_EQ(string_as_str(s), "Base");

    // string_from NULL
    string_t *empty = string_from(NULL);
    ASSERT_PTR(empty);
    ASSERT_EQ(string_len(empty), 0);
    string_drop(s);
    string_drop(empty);
    return 0;
}

static int test_drop(void)
{
    string_t *s = string_from("Temporary");
    string_drop(s);
    return 0;
}

/* ================= Test Suite Registration ================= */
static struct test_case string_tests[] = {
    { "test_string_new",       test_string_new },
    { "test_string_from",      test_string_from },
    { "test_string_push_char", test_string_push_char },
    { "test_string_push_str",  test_string_push_str },
    { "test_capacity_growth",  test_capacity_growth },
    { "test_concatenation",    test_concatenation },
    { "test_null_safety",      test_null_safety },
    { "test_drop",             test_drop },
};

static struct test_suite string_suite = {
    .name = "String_t Tests",
    .cases = string_tests,
    .count = sizeof(string_tests) / sizeof(string_tests[0]),
};

/* ================= Main Entry ================= */
int main(void)
{
    printf("====================================\n");
    run_test_suite(&string_suite);
    print_test_summary();
    return (_test_stats.failed > 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}
