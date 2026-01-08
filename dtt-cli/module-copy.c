#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>

#include "dtt.h"
#include "modules.h"
#include "common.h"
#include "helper.h"

static char* mmap_file_content(const char *filename, size_t *file_size)
{
    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        perror("open file for mmap");
        return NULL;
    }

    struct stat sb;
    if (fstat(fd, &sb) == -1) {
        perror("fstat");
        close(fd);
        return NULL;
    }

    *file_size = sb.st_size;
    if (*file_size == 0) {
        fprintf(stderr, "File is empty\n");
        close(fd);
        return NULL;
    }

    char *file_content = mmap(NULL, *file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file_content == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return NULL;
    }

    close(fd);
    return file_content;
}

static void unmap_file_content(char *file_content, size_t file_size)
{
    if (file_content != NULL) {
        munmap(file_content, file_size);
    }
}

static void fill_copy_output(char *output, int len, const char *src, const char *dest)
{
    snprintf(output, len - 1, "\"msg\": \"copied %s to %s\"\n", src, dest);
}

module_result_t module_copy(const char *ipv4, const char *src, const char *dest)
{
    module_result_t res = {0};
    uint32_t ssid;
    struct stat file_stat;
    mode_t permissions;
    size_t file_size = 0;

    res.rc = -1;
    res.changed = 0;

    if (stat(src, &file_stat) == -1) {
        res.rc = errno;
        res.output = calloc(1, 128);
        snprintf(res.output, 128 - 1, "%s", strerror(errno));
        return res;
    }

    if (ipv4_to_uint32(ipv4, &ssid) == 0) {
        permissions = file_stat.st_mode & 07777;
        char *file_content = mmap_file_content(src, &file_size);

        if (!file_content) {
            return res;
        }

        int result = dt_file_write(ssid, dest, 0, file_size, file_content);
        if (result <= 0) {
            unmap_file_content(file_content, file_size);
            return res;
        }
        unmap_file_content(file_content, file_size);
        dt_file_chmod(ssid, dest, permissions);

        res.rc = 0;
        res.output = calloc(1, 8192);
        fill_copy_output(res.output, 8192, src, dest);
        res.changed = 1;
    }

    return res;
}

module_result_t module_ssh_copy(const char *host, const char *src, const char *dest)
{
    module_result_t res = {0};

    char cmd[BUF_SIZE_LARGE];
    snprintf(cmd, sizeof(cmd),
             "scp -o ConnectTimeout=10 -o BatchMode=yes -o StrictHostKeyChecking=no \"%s\" %s:\"%s\" 2>&1",
             src, host, dest);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        res.rc = -1;
        return res;
    }

    res.output = malloc(8192);
    size_t n = fread(res.output, 1, 8191, fp);
    res.output[n] = '\0';
    res.rc = WEXITSTATUS(pclose(fp));

    // changed if scp exits with 0 and no error output
    if (res.rc == 0 && strstr(res.output, "No such file") == NULL) {
        res.changed = 1;
        fill_copy_output(res.output, 8192, src, dest);
    }

    return res;
}
