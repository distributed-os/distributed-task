#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "test.h"
#include "dynarray.h"

/* ------------------------------------------------------------------ */
/* Test data structures */
struct test_obj {
    int         id;
    char        tag[16];
    long        value;
};

/* Helper to create a test object */
static struct test_obj *make_obj(int id)
{
    struct test_obj *obj = malloc(sizeof(*obj));
    if (!obj)
        return NULL;
    obj->id = id;
    snprintf(obj->tag, sizeof(obj->tag), "obj%d", id);
    obj->value = id * 1000L;
    return obj;
}

static void free_obj(void *p)
{
    free(p);
}

/* ------------------------------------------------------------------ */
/* Test cases */

static int test_basic_init_destroy(void)
{
    struct dynarray da = DYNARRAY_INIT(da);
    ASSERT_EQ(dynarray_size(&da), 0);
    dynarray_destroy(&da);
    return 0;
}

static int test_append_and_get(void)
{
    struct dynarray da = DYNARRAY_INIT(da);
    struct test_obj *o1, *o2, *got;

    o1 = make_obj(1);
    o2 = make_obj(2);
    ASSERT_PTR(o1);
    ASSERT_PTR(o2);

    ASSERT_TRUE(dynarray_append(&da, o1) == 0);
    ASSERT_TRUE(dynarray_append(&da, o2) == 0);
    ASSERT_EQ(dynarray_size(&da), 2);

    got = dynarray_get(&da, 0);
    ASSERT_PTR(got);
    ASSERT_EQ(got->id, 1);

    got = dynarray_get(&da, 1);
    ASSERT_PTR(got);
    ASSERT_EQ(got->id, 2);

    ASSERT_NULL(dynarray_get(&da, 2));

    /* cleanup */
    for (size_t i = 0; i < dynarray_size(&da); i++)
        free_obj(dynarray_get(&da, i));
    dynarray_destroy(&da);
    return 0;
}

static int test_remove(void)
{
    struct dynarray da = DYNARRAY_INIT(da);
    struct test_obj *objs[10];
    struct test_obj *got;

    for (int i = 0; i < 10; i++) {
        objs[i] = make_obj(i);
        dynarray_append(&da, objs[i]);
    }
    ASSERT_EQ(dynarray_size(&da), 10);

    /* remove middle */
    ASSERT_TRUE(dynarray_remove(&da, 5) == 0);
    ASSERT_EQ(dynarray_size(&da), 9);
    got = dynarray_get(&da, 5);
    ASSERT_EQ(got->id, 6);

    /* remove first */
    ASSERT_TRUE(dynarray_remove(&da, 0) == 0);
    ASSERT_EQ(dynarray_size(&da), 8);
    got = dynarray_get(&da, 0);
    ASSERT_EQ(got->id, 1);

    /* remove last */
    ASSERT_TRUE(dynarray_remove(&da, 7) == 0);
    ASSERT_EQ(dynarray_size(&da), 7);

    /* invalid index */
    ASSERT_TRUE(dynarray_remove(&da, 100) == -EINVAL);

    /* cleanup */
    for (size_t i = 0; i < dynarray_size(&da); i++)
        free_obj(dynarray_get(&da, i));
    dynarray_destroy(&da);
    return 0;
}

static int test_grow_realloc(void)
{
    struct dynarray da = DYNARRAY_INIT(da);

    for (int i = 0; i < 1000; i++) {
        ASSERT_TRUE(dynarray_append(&da, make_obj(i)) == 0);
    }
    ASSERT_EQ(dynarray_size(&da), 1000);

    struct test_obj *obj = dynarray_get(&da, 999);
    ASSERT_EQ(obj->id, 999);

    /* cleanup */
    for (size_t i = 0; i < dynarray_size(&da); i++)
        free_obj(dynarray_get(&da, i));
    dynarray_destroy(&da);
    return 0;
}

static int test_iterator_basic(void)
{
    struct dynarray da = DYNARRAY_INIT(da);
    struct dynarray_iter iter;
    void *elem;
    int count = 0;
    int ids[] = {10, 20, 30, 40, 50};

    for (int i = 0; i < 5; i++)
        dynarray_append(&da, make_obj(ids[i]));

    dynarray_iter_init(&da, &iter);
    while (dynarray_iter_next(&iter, &elem) > 0) {
        struct test_obj *obj = elem;
        ASSERT_EQ(obj->id, ids[count++]);
    }
    ASSERT_EQ(count, 5);

    /* cleanup */
    for (size_t i = 0; i < dynarray_size(&da); i++)
        free_obj(dynarray_get(&da, i));
    dynarray_destroy(&da);
    return 0;
}

static int test_iterator_concurrent_modification(void)
{
    struct dynarray da = DYNARRAY_INIT(da);
    struct dynarray_iter iter;
    void *elem;
    int rc;

    for (int i = 0; i < 10; i++)
        dynarray_append(&da, make_obj(i));

    dynarray_iter_init(&da, &iter);

    /* First element - OK */
    rc = dynarray_iter_next(&iter, &elem);
    ASSERT_EQ(rc, 1);

    /* Now modify the array - this should invalidate the iterator */
    dynarray_append(&da, make_obj(999));

    /* Next iteration should detect invalidation */
    rc = dynarray_iter_next(&iter, &elem);
    ASSERT_EQ(rc, -EINVAL);

    /* cleanup */
    for (size_t i = 0; i < dynarray_size(&da); i++)
        free_obj(dynarray_get(&da, i));
    dynarray_destroy(&da);
    return 0;
}

/* Thread that continuously adds items */
static void *concurrent_producer(void *arg)
{
    struct dynarray *da = arg;
    for (int i = 0; i < 500; i++) {
        struct test_obj *obj = make_obj(1000 + i);
        if (dynarray_append(da, obj) != 0)
            free(obj);
        usleep(100);
    }
    return NULL;
}

static int test_iterator_concurrent_stress(void)
{
    struct dynarray da = DYNARRAY_INIT(da);
    struct dynarray_iter iter;
    void *elem;
    int rc;
    int seen = 0;
    pthread_t thread;

    pthread_create(&thread, NULL, concurrent_producer, &da);

    /* Keep iterating as fast as possible */
    for (int round = 0; round < 100; round++) {
        dynarray_iter_init(&da, &iter);
        while ((rc = dynarray_iter_next(&iter, &elem)) > 0) {
            struct test_obj *obj = elem;
            if (obj->id >= 1000)
                seen++;
        }
        if (rc < 0) {
            /* Expected: iterator invalidated - just restart */
        }
        usleep(500);
    }

    pthread_join(thread, NULL);
    ASSERT_TRUE(seen > 0);  /* must have seen some producer objects */

    /* cleanup */
    for (size_t i = 0; i < dynarray_size(&da); i++)
        free_obj(dynarray_get(&da, i));
    dynarray_destroy(&da);
    return 0;
}

static int test_for_each(void)
{
    struct dynarray da = DYNARRAY_INIT(da);
    struct test_obj *obj;
    int count = 0;

    for (int i = 0; i < 5; i++)
        ASSERT_TRUE(dynarray_append(&da, make_obj(i)) == 0);

    dynarray_for_each(obj, &da) {
        ASSERT_EQ(obj->id, count);
        count++;
    }
    ASSERT_EQ(count, 5);

    for (size_t i = 0; i < dynarray_size(&da); i++)
        free_obj(dynarray_get(&da, i));
    dynarray_destroy(&da);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Test suite definition */

static struct test_case dynarray_tests[] = {
    { "basic_init_destroy",               test_basic_init_destroy },
    { "append_and_get",                   test_append_and_get },
    { "remove",                           test_remove },
    { "grow_realloc",                     test_grow_realloc },
    { "iterator_basic",                   test_iterator_basic },
    { "iterator_concurrent_modification", test_iterator_concurrent_modification },
    { "iterator_concurrent_stress",       test_iterator_concurrent_stress },
    { "for_each",                         test_for_each },
};

static struct test_suite dynarray_suite = {
    .name  = "dynarray",
    .cases = dynarray_tests,
    .count = sizeof(dynarray_tests) / sizeof(dynarray_tests[0]),
};

/* ------------------------------------------------------------------ */
int main(void)
{
    printf("====================================\n");

    run_test_suite(&dynarray_suite);
    print_test_summary();

    return _test_stats.failed > 0 ? 1 : 0;
}
