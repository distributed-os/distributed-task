#ifndef __DYNARRAY_H__
#define __DYNARRAY_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <inttypes.h>

/*
 * The dynamic array itself
 */
struct dynarray {
    void           **data;       /* array of pointers */
    size_t           size;
    size_t           capacity;
    uint64_t         generation; /* increased on every structural change */
};

/*
 *  Iterator
 */
struct dynarray_iter {
    struct dynarray *da;
    size_t           pos;
    uint64_t         generation;
};

/* ------------------------------------------------------------------ */
/* Internal helpers */
static inline void __bump_generation(struct dynarray *da)
{
    da->generation++;
}

static int __dynarray_grow(struct dynarray *da)
{
    size_t new_cap = (da->capacity == 0) ? 8 : da->capacity * 2;
    void **new_data;

    if (!da->data) {
        new_data = malloc(new_cap * sizeof(void *));
    } else {
        new_data = realloc(da->data, new_cap * sizeof(void *));
    }
    if (!new_data)
        return -ENOMEM;

    da->data     = new_data;
    da->capacity = new_cap;
    __bump_generation(da);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Public API */
#define DYNARRAY_INIT(name) { \
    .data       = NULL,       \
    .size       = 0,          \
    .capacity   = 0,          \
    .generation = 0,          \
}

static inline void dynarray_destroy(struct dynarray *da)
{
    if (da->data != NULL) {
        free(da->data);
    }
    da->data     = NULL;
    da->size     = 0;
    da->capacity = 0;
}

static inline int dynarray_append(struct dynarray *da, void *element)
{
    int rc = 0;

    if (da->size == da->capacity) {
        if (__dynarray_grow(da)) {
            rc = -ENOMEM;
            goto out;
        }
    }
    da->data[da->size++] = element;
    __bump_generation(da);
out:
    return rc;
}

static inline int dynarray_remove(struct dynarray *da, size_t idx)
{
    int rc = -EINVAL;

    if (idx >= da->size)
        goto out;

    memmove(&da->data[idx], &da->data[idx + 1],
            (da->size - idx - 1) * sizeof(void *));
    da->size--;
    __bump_generation(da);
    rc = 0;
out:
    return rc;
}

static inline size_t dynarray_size(struct dynarray *da)
{
    return da->size;
}

static inline void *dynarray_get(struct dynarray *da, size_t idx)
{
    void *elem = NULL;

    if (idx < da->size)
        elem = da->data[idx];
    return elem;
}

static inline struct dynarray_iter *dynarray_iter_init(struct dynarray *da, struct dynarray_iter *iter)
{
    iter->da         = da;
    iter->pos        = 0;
    iter->generation = da->generation;
    return iter;
}

/*
 * Returns:
 *   1  -> valid element returned in *elem
 *   0  -> end of array
 *  -EINVAL -> iterator invalidated (concurrent modification)
 */
static inline int dynarray_iter_next(struct dynarray_iter *iter, void **elem)
{
    struct dynarray *da = iter->da;
    int rc = -EINVAL;

    if (iter->generation != da->generation)
        goto out;

    if (iter->pos >= da->size) {
        rc = 0;
        goto out;
    }

    *elem = da->data[iter->pos++];
    rc = 1;

out:
    return rc;
}

#define dynarray_for_each(pos, da)                                    \
    for (struct dynarray_iter __iter,                                 \
            *__iter_ptr = dynarray_iter_init((da), &__iter);          \
            dynarray_iter_next(__iter_ptr, (void **)&(pos)) > 0;)

#endif /* __DYNARRAY_H__ */
