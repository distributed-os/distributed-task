#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "md5.h"

int hostname_to_ipv4(const char *hostname, char *ipv4, size_t len)
{
    struct addrinfo hints, *res, *p;

    // INET_ADDRSTRLEN is 16
    if (len < 16)
        return -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;       // IPv4
    hints.ai_socktype = SOCK_STREAM; // TCP socket

    int status = getaddrinfo(hostname, NULL, &hints, &res);
    if (status != 0) {
        return -1;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        void *addr;
        struct sockaddr_in *in = (struct sockaddr_in *)p->ai_addr;
        addr = &(in->sin_addr);
        inet_ntop(p->ai_family, addr, ipv4, len);
    }

    freeaddrinfo(res);
    return 0;
}

int ipv4_to_uint32(const char *ip_str, uint32_t *result)
{
    if (ip_str == NULL || result == NULL) {
        return -1;
    }

    struct in_addr addr;

    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        return -1;
    }

    *result = ntohl(addr.s_addr);
    return 0;
}

int uint32_to_ipv4(uint32_t val, char *ip_str)
{
    if (ip_str == NULL) {
        return -1;
    }

    struct in_addr addr;

    addr.s_addr = htonl(val);

    if (inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN) == NULL) {
        return -1;
    }

    return 0;
}

uint32_t random_uint32()
{
    static int seeded = 0;
    FILE *file = fopen("/proc/sys/kernel/random/uuid", "r");
    char uuid[40] = {0};
    char hex_str[8] = {0};
    size_t idx = 0;
    uint32_t result = 0;

    if (!file) {
        if (!seeded) {
            srand(time(NULL));
            seeded = 1;
        }
        return (uint32_t)rand() & ((1U << 31) - 1);
    }

    if (fgets(uuid, sizeof(uuid), file) == NULL) {
        fclose(file);
        return -1;
    }
    fclose(file);

    uuid[strcspn(uuid, "\n")] = '\0';

    for (int i = 0; uuid[i] != '\0' && idx < 8; i++) {
        if ((uuid[i] >= '1' && uuid[i] <= '9') ||
                (uuid[i] >= 'a' && uuid[i] <= 'f') ||
                (uuid[i] >= 'A' && uuid[i] <= 'F')) {
            hex_str[idx++] = uuid[i];
        }
    }

    while (idx < sizeof(hex_str)) {
        hex_str[idx++] = '0';
    }

    for (int i = 0; i < 8; i++) {
        result = result * 16 + (hex_str[i] >= '0' &&
                hex_str[i] <= '9' ? hex_str[i] - '0' : (hex_str[i] >= 'a' &&
                    hex_str[i] <= 'f' ? hex_str[i] - 'a' + 10 : hex_str[i] - 'A' + 10));
    }

    return result & ((1U << 31) - 1);
}

uint64_t random_uint64()
{
    static int seeded = 0;
    FILE *file = fopen("/proc/sys/kernel/random/uuid", "r");
    char uuid[40] = {0};
    char hex_str[16] = {0};
    size_t idx = 0;
    uint64_t result = 0;

    if (!file) {
        if (!seeded) {
            srand(time(NULL));
            seeded = 1;
        }
        return (((uint64_t)rand() << 32) | (uint64_t)rand()) & ((1ULL << 63) - 1);
    }

    if (fgets(uuid, sizeof(uuid), file) == NULL) {
        fclose(file);
        return -1;
    }
    fclose(file);

    uuid[strcspn(uuid, "\n")] = '\0';

    for (int i = 0; uuid[i] != '\0' && idx < 16; i++) {
        if ((uuid[i] >= '1' && uuid[i] <= '9') ||
                (uuid[i] >= 'a' && uuid[i] <= 'f') ||
                (uuid[i] >= 'A' && uuid[i] <= 'F')) {
            hex_str[idx++] = uuid[i];
        }
    }

    while (idx < sizeof(hex_str)) {
        hex_str[idx++] = '0';
    }

    for (int i = 0; i < 16; i++) {
        result = result * 16 + (hex_str[i] >= '0' &&
                hex_str[i] <= '9' ? hex_str[i] - '0' : (hex_str[i] >= 'a' &&
                    hex_str[i] <= 'f' ? hex_str[i] - 'a' + 10 : hex_str[i] - 'A' + 10));
    }

    return result & ((1ULL << 63) - 1);
}

const char* basename_from_path(const char* path)
{
    if (!path) return NULL;

    const char* last_slash = strrchr(path, '/');

    if (last_slash == NULL) {
        return path;
    }

    return last_slash + 1;
}

int file_stat_mode(const char *filename, mode_t *mode)
{
    struct stat st;
    if (stat(filename, &st) == -1) {
        perror("stat local file");
        return -1;
    }
    *mode = st.st_mode & 0777;
    return 0;
}

int file_calculate_md5(const char *filename, char *md5sum)
{
    md5_ctx_t context;
    unsigned char buffer[1024];
    unsigned char digest[16];
    size_t bytes;
    int i;

    FILE *file = fopen(filename, "rb");
    if (!file) {
        return -1;
    }

    md5_init(&context);

    while ((bytes = fread(buffer, 1, 1024, file)) != 0) {
        md5_update(&context, buffer, bytes);
    }

    md5_final(digest, &context);
    fclose(file);

    for (i = 0; i < 16; i++) {
        sprintf(md5sum + (i * 2), "%02x", digest[i]);
    }
    md5sum[32] = '\0';

    return 0;
}
