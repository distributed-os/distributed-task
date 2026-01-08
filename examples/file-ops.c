#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>

#include "dtt.h"

// Helper function to read file content using mmap
static char* mmap_file_content(const char *filename, size_t *file_size)
{
    int fd = open(filename, O_RDONLY);
    if (fd == -1) {
        perror("open file for mmap");
        return NULL;
    }

    // Get file size
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

    // Memory-map the file
    char *file_content = mmap(NULL, *file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file_content == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return NULL;
    }

    close(fd); // File descriptor can be closed after successful mapping
    return file_content;
}

// Unmap memory-mapped file
static void unmap_file_content(char *file_content, size_t file_size)
{
    if (file_content != NULL) {
        munmap(file_content, file_size);
    }
}

int run_filewrite(char *tmpfile)
{
    char path[128] = { 0 };
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len <= 0) {
        perror("readlink");
        return -1;
    }

    // Read file content using mmap
    size_t file_size = 0;
    char *file_content = mmap_file_content(path, &file_size);
    if (!file_content) {
        fprintf(stderr, "Failed to mmap file: %s\n", path);
        return -1;
    }

    int result = dt_file_write(0, tmpfile, 0, file_size, file_content);
    if (result <= 0) {
        fprintf(stderr, "dt_file_write failed with result: %d\n", result);
        unmap_file_content(file_content, file_size);
        return -1;
    }

    printf("File write %s completed successfully!\n", path);

    // Clean up memory mapping
    unmap_file_content(file_content, file_size);
    return 0;
}

void run_filestat(char *tmpfile)
{
    dt_filestat_t *st = (dt_filestat_t *)calloc(1, sizeof(dt_filestat_t));
    int result = dt_file_stat(0, tmpfile, st);
    if (result != 0) {
        free(st);
        fprintf(stderr, "dt_file_stat failed with result: %d\n", result);
        return;
    }
    printf("File stat %s: %c %04o %ld\n", tmpfile, st->type, st->mode, st->size);
    free(st);
}

void run_filehash(char *tmpfile)
{
    dt_filehash_t *fi = (dt_filehash_t *)calloc(1, sizeof(dt_filehash_t));
    int result = dt_file_hash(0, tmpfile, fi);
    if (result != 0) {
        free(fi);
        fprintf(stderr, "dt_file_hash failed with result: %d\n", result);
        return;
    }
    printf("File md5sum %s: %s\n", tmpfile, fi->md5sum);
    free(fi);
}

int run_fileread(char *tmpfile)
{
    size_t size = 1024 * 1024;
    char *buf = (char *)malloc(1024 * 1024);
    char path[32] = { 0 };
    char cmd[32] = { 0 };

    sprintf(path, "%s.bak", tmpfile);

    int result = dt_file_read(0, tmpfile, 0, size, buf);
    if (result <= 0) {
        fprintf(stderr, "dt_file_read failed with result: %d\n", result);
        free(buf);
        return -1;
    }

    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd > 0) {
        if (write(fd, buf, result) > 0) {
            FILE *fp;
            sprintf(cmd, "md5sum %s", path);
            fp = popen(cmd, "r");
            if (fp) {
                while (fgets(buf, sizeof(buf), fp) != NULL) {
                    printf("%s", buf);
                }
                pclose(fp);
            }
        }
        close(fd);
        remove(path);
    }

    free(buf);
}

void run_remove(char *tmpfile)
{
    int result = dt_file_remove(0, tmpfile);
    if (result != 0) {
        fprintf(stderr, "dt_file_remove failed with result: %d\n", result);
        return;
    }
    printf("File remove %s successfully!\n", tmpfile);
}

void run_chmod(char *tmpfile)
{
    int result = dt_file_chmod(0, tmpfile, 0755);
    if (result != 0) {
        fprintf(stderr, "dt_file_chmod failed with result: %d\n", result);
        return;
    }
    printf("File chmod %s successfully!\n", tmpfile);
}

int main()
{
    char tmppath[] = "/tmp/file-ops-XXXXXX";
    char *tmpfile = mkdtemp(tmppath);
    rmdir(tmpfile);

    dt_init();

    printf("\033[31mNOTICE: This example can only be run on a single node !!!\033[0m\n");

    run_filewrite(tmpfile);
    run_filestat(tmpfile);
    run_chmod(tmpfile);
    run_filestat(tmpfile);
    run_filehash(tmpfile);
    run_fileread(tmpfile);
    run_remove(tmpfile);

    return 0;
}
