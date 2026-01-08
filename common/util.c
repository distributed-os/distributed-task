/* util.c
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

void *xmalloc(unsigned int size)
{
    void *ptr = malloc(size);

    if (size && !ptr) {
        return NULL;
    }
    memset(ptr, 0, size);
    return ptr;
}

void xfree(void *ptr)
{
    if (ptr) {
        free(ptr);
    }
    ptr = NULL;
}


size_t xread(int fd, void *buf, size_t size)
{
    ssize_t total = 0;

    while (size) {
        ssize_t ret;
        ret = read(fd, buf, size);

        if (ret < 0 && errno == EINTR)
            continue;

        if (ret <= 0)
            break;

        buf = (char *) buf + ret;
        size -= ret;
        total += ret;
    }

    return total;
}

size_t xwrite(int fd, const char *buf, size_t size)
{
    ssize_t total = 0;

    while (size) {
        ssize_t ret;
        ret = write(fd, buf, size);

        if (ret < 0 && errno == EINTR)
            continue;

        if (ret <= 0)
            break;

        buf = (const char *) buf + ret;
        size -= ret;
        total += ret;
    }

    return total;
}

off_t xfile_size(const char *path)
{
    struct stat st;

    if (stat(path, &st) == -1) {
        return -1;
    }
    return st.st_size;
}