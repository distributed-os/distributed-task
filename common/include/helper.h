#ifndef __HELPER_H__
#define __HELPER_H__

#include <stdint.h>
#include <endian.h>

#define BUF_SIZE_256    256
#define BUF_SIZE_512    512
#define BUF_SIZE_1K     1024
#define BUF_SIZE_4K     4096
#define BUF_SIZE_8K     8192
#define BUF_SIZE_16K    16384
#define BUF_SIZE_64K    65536

#define BUF_SIZE_SMALL     BUF_SIZE_256
#define BUF_SIZE_NORMAL    BUF_SIZE_1K
#define BUF_SIZE_LARGE     BUF_SIZE_4K
#define BUF_SIZE_HUGE      BUF_SIZE_64K

inline uint64_t hton64(uint64_t host)
{
    return htole64(host);
}

inline uint64_t ntoh64(uint64_t net)
{
    return le64toh(net);
}

inline uint32_t hton32(uint32_t host)
{
    return htole32(host);
}

inline uint32_t ntoh32(uint32_t net)
{
    return le32toh(net);
}

inline uint16_t hton16(uint16_t host)
{
    return htole16(host);
}

inline uint16_t ntoh16(uint16_t net)
{
    return le16toh(net);
}

int hostname_to_ipv4(const char *hostname, char *ipv4, size_t len);
int ipv4_to_uint32(const char *ip_str, uint32_t *result);
int uint32_to_ipv4(uint32_t val, char *ip_str);
uint32_t random_uint32();
uint64_t random_uint64();
const char* basename_from_path(const char* path);
int file_stat_mode(const char *filename, mode_t *mode);
int file_calculate_md5(const char *filename, char *md5sum);

#endif
