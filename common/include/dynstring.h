#ifndef __DYNSTRING_H__
#define __DYNSTRING_H__

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

typedef struct {
    char *ptr;
    size_t len;
    size_t cap;
} string_t;

// ---------------------- Internal Helper ----------------------
static inline void string_reserve_internal(string_t *s, size_t new_cap)
{
    if (new_cap <= s->cap) {
        return;
    }
    char *new_ptr = realloc(s->ptr, new_cap);
    if (!new_ptr) {
        return;
    }
    s->ptr = new_ptr;
    s->cap = new_cap;
}

// ---------------------- Public Methods ----------------------
static inline string_t* string_new(void)
{
    string_t *s = malloc(sizeof(string_t));
    if (!s) return NULL;
    s->ptr = NULL;
    s->len = 0;
    s->cap = 0;
    return s;
}

static inline string_t* string_from(const char *cstr)
{
    string_t *s = string_new();
    if (!cstr) return s;
    size_t len = strlen(cstr);
    s->ptr = malloc(len + 1);
    if (!s->ptr) {
        free(s);
        return NULL;
    }
    memcpy(s->ptr, cstr, len + 1);
    s->len = len;
    s->cap = len;
    return s;
}

static inline void string_drop(string_t *s)
{
    if (s) {
        if (s->ptr) {
            free(s->ptr);
            s->ptr = NULL;
        }
        free(s);
    }
}

static inline void string_push(string_t *s, char c)
{
    if (s->len + 1 >= s->cap) {
        size_t new_cap = (s->cap == 0) ? 4 : s->cap * 2;
        string_reserve_internal(s, new_cap);
    }
    s->ptr[s->len] = c;
    s->len++;
    if (s->len > 1)
       s->ptr[s->len] = '\0';
}

static inline void string_push_str(string_t *s, const char *str)
{
    if (!str) return;
    size_t add_len = strlen(str);
    if (add_len == 0) return;
    if (s->len + add_len >= s->cap) {
        size_t new_cap = s->cap;
        while (new_cap <= s->len + add_len) {
            new_cap = (new_cap == 0) ? 4 : new_cap * 2;
        }
        string_reserve_internal(s, new_cap);
    }
    memcpy(s->ptr + s->len, str, add_len);
    s->len += add_len;
    s->ptr[s->len] = '\0';
}

static inline const char* string_as_str(const string_t *s)
{
    return s->ptr ? s->ptr : "";
}

static inline size_t string_len(const string_t *s)
{
    return s->len;
}

static inline size_t string_cap(const string_t *s)
{
    return s->cap;
}

static inline void string_debug(const string_t *s) {
    printf("String { ptr: %p, len: %zu, cap: %zu, value: \"%s\" }\n",
            (void*)s->ptr, s->len, s->cap, string_as_str(s));
}

#endif
