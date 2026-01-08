#ifndef __DTT_H__
#define __DTT_H__

#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t dt_ssid_t;

typedef struct {
    uint64_t low;
    uint64_t high;
    uint64_t offset;
    uint64_t size;
    uint64_t mmap_ptr;
} dt_addr_t;

dt_addr_t *dt_addr_offset(dt_addr_t *addr, size_t offset);
dt_addr_t *dt_addr_add(dt_addr_t *addr, size_t len);
dt_addr_t *dt_addr_sub(dt_addr_t *addr, size_t len);

#define DT_ADDR2SSID(addr) ((dt_ssid_t)(addr->high))

typedef struct {
    uint64_t len;
    char *data;
} dt_buf_t;

typedef struct {
    uint64_t outlen;
    uint64_t errlen;
    char *out;
    char *err;
    int result;
} dt_ret_t;

typedef void (*dt_func_t)(dt_buf_t *args, dt_buf_t *ret);

typedef struct {
    char *name;
    dt_func_t func;
} dt_entry_t;
#define DT_TASK_SIZE 1024
#define DT_DECLARE_TASK_ARRAY                     \
    extern dt_entry_t dt_task_arry[DT_TASK_SIZE]; \
    extern size_t dt_task_len
DT_DECLARE_TASK_ARRAY;

#define DT_DECLARE_TASK(value)                                             \
    __attribute__((constructor)) static void _append_##value() {           \
        if (dt_task_len < sizeof(dt_task_arry)/sizeof(dt_task_arry[0])) {  \
            dt_task_arry[dt_task_len].func = value;                        \
            dt_task_arry[dt_task_len].name = (char *)(#value);             \
            dt_task_len++;                                                 \
        }                                                                  \
    }

#define LB_RANDOM       0x0
#define LB_ROUND_ROBIN  0x1
#define LB_LOAD_AWARE   0x2

// node ops
int dt_ping(dt_ssid_t ssid);
int dt_loglevel_get(dt_ssid_t ssid);
int dt_loglevel_set(dt_ssid_t ssid, int level);

// task ops
int dt_init();
void dt_set_loadbalance(int lb);
int dt_join(int32_t task_id);
int32_t _dt_task_create(dt_ssid_t ssid, const char *name, dt_buf_t *args, dt_buf_t *ret);
#define dt_task_create(ssid, fn, args, ret) _dt_task_create(ssid, #fn, args, ret)
int32_t dt_cmd_create(dt_ssid_t ssid, const char *cmd, dt_ret_t *ret);

// file ops
typedef struct{
    char md5sum[40];
} dt_filehash_t;

typedef struct{
    char type;
    uint16_t mode;
    uint64_t size;
} dt_filestat_t;

int dt_file_stat(dt_ssid_t ssid, const char *path, dt_filestat_t *st);
int dt_file_chmod(dt_ssid_t ssid, const char *path, uint16_t mode);
int dt_file_hash(dt_ssid_t ssid, const char *path, dt_filehash_t *fh);
int dt_file_remove(dt_ssid_t ssid, const char *path);
int dt_file_write(dt_ssid_t ssid, const char *path, uint64_t offset, uint64_t len, char *data);
int dt_file_read(dt_ssid_t ssid, const char *path, uint64_t offset, uint64_t len, char *data);

// memory ops
dt_addr_t *dt_malloc(dt_ssid_t ssid, size_t size);
int dt_free(dt_addr_t *addr);
void *dt_mmap(dt_addr_t *addr);
void dt_munmap(dt_addr_t *addr);
int dt_memset(dt_addr_t *addr, char val, size_t len);
void *dt_memcpy_from(void *to, dt_addr_t *from, size_t len);
dt_addr_t *dt_memcpy_to(dt_addr_t *to, void *from, size_t len);
dt_addr_t *dt_memcpy(dt_addr_t *to, dt_addr_t *from, size_t len);

#ifdef __cplusplus
}
#endif

#endif
