#ifndef __UTIL_H__
#define __UTIL_H__

#include <stddef.h>
#include <sys/types.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define streq(s1, s2) (!strcmp((s1), (s2)))

#define strcaseeq(s1, s2) (!strcasecmp((s1), (s2)))

#ifndef min
#define min(x, y) ({                    \
        typeof(x) _min1 = (x);          \
        typeof(y) _min2 = (y);          \
        (void) (&_min1 == &_min2);      \
        _min1 < _min2 ? _min1 : _min2; })
#endif

#ifndef max
#define max(x, y) ({                    \
        typeof(x) _max1 = (x);          \
        typeof(y) _max2 = (y);          \
        (void) (&_max1 == &_max2);      \
        _max1 > _max2 ? _max1 : _max2; })
#endif

void *xmalloc(unsigned int size);
void xfree(void *ptr);
size_t xread(int fd, void *buf, size_t size);
size_t xwrite(int fd, const char *buf, size_t size);
off_t xfile_size(const char *path);

#endif
