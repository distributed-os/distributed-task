#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <inttypes.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include "util.h"
#include "log.h"
#include "helper.h"
#include "memory.h"
#include "dtt.h"

static inline size_t bits_rounded_up_to_multiple_of_4(size_t size)
{
    unsigned int bits = 0;
    if (size <= 1)
        return 4;

#if defined(__GNUC__) || defined(__clang__)
    // Use GCC/Clang built-in function
    bits = sizeof(size_t) * 8 - __builtin_clzll(size - 1);
#else
    size_t temp = size - 1;
    while (temp) {
        temp >>= 1;
        bits++;
    }
#endif

    // Round up to nearest multiple of 4: (bits + 3) & ~3U
    return (size_t)((bits + 3U) & ~3U);
}

static uint64_t random_uint64_no_zero_in_hex(void)
{
    int has_internal_zero = 0;
    int i;
    int times = 0;
    char hex[20] = { 0 };
    uint64_t value = random_uint64();

    while (times++ < 1024) {
        // Convert to lowercase 16-digit hex string (fixed 16 chars, zero-padded)
        snprintf(hex, sizeof(hex), "%016lx", (uint64_t)value);

        has_internal_zero = 0;
        for (i = 0; i < 16; i++) { // Check from the first character
            if (hex[i] == '0') {
                has_internal_zero = 1;
                break;
            }
        }

        if (!has_internal_zero) {
            return value;  // Condition satisfied, return directly
        }
        // Otherwise continue loop and regenerate
        value = random_uint64();
    }
    return value;
}

static uint64_t random_addr_with_size(size_t size)
{
    size_t bits = bits_rounded_up_to_multiple_of_4(size) + 4;
    uint64_t ret = random_uint64_no_zero_in_hex();

    ret <<= bits;
    return ret | size;
}

static void memory_malloc(const struct dt_req_malloc *req, struct dt_rsp_malloc *rsp)
{
    char path[128] = { 0 };
    uint64_t addr = random_addr_with_size(req->size);

    memset(rsp, 0, sizeof(struct dt_rsp_malloc));
    rsp->high = req->ssid;

    snprintf(path, sizeof(path), "%s-%016" PRIx64, SHM_PREFIX, addr);
    int fd = shm_open(path, O_CREAT | O_RDWR, 0666);
    if (fd == -1) {
        perror("shm_open");
        pr_err("shm_open %s failed", path);
        return;
    }
    if (ftruncate(fd, req->size) == -1) {
        perror("ftruncate");
        shm_unlink(path);
        return;
    }

    close(fd);
    rsp->low = addr;
}

static void memory_free(const struct dt_req_free *req, struct dt_rsp_free *rsp)
{
    char path[128] = { 0 };

    memset(rsp, 0, sizeof(struct dt_rsp_free));

    snprintf(path, sizeof(path), "%s-%016" PRIx64, SHM_PREFIX, req->low);

    shm_unlink(path);
    rsp->retval = 0;
}

static void memory_memset(const struct dt_req_memset *req, struct dt_rsp_memset *rsp)
{
    int fd;
    void *addr;
    char path[128] = { 0 };

    memset(rsp, 0, sizeof(struct dt_rsp_memset));

    snprintf(path, sizeof(path), "%s-%016" PRIx64, SHM_PREFIX, req->low);

    fd = shm_open(path, O_RDWR, 0666);
    if (fd == -1) {
        perror("shm_open failed");
        pr_err("shm_open %s failed", path);
        rsp->retval = -1;
        return;
    }
    addr = mmap(0, req->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        perror("mmap failed");
        close(fd);
        rsp->retval = -1;
        return;
    }
    close(fd);

    memset(addr + req->offset, req->val, req->len);
    munmap(addr, req->size);

    rsp->retval = 0;
}

static dt_message_t *build_malloc_reply(dt_message_t *msg)
{
    struct dt_rsp_malloc *rsp = NULL;
    struct dt_req_malloc *req = NULL;

    dt_message_t *msg_reply = xmalloc(sizeof(dt_message_t));
    if (!msg_reply) {
        pr_err("calloc failed");
        return NULL;
    }

    msg_reply->header.cmd = CMD_RSP_MALLOC;
    msg_reply->header.id = msg->header.id;
    msg_reply->header.buf_size = sizeof(struct dt_rsp_malloc);

    msg_reply->buf = xmalloc(msg_reply->header.buf_size);
    if (!msg_reply->buf) {
        perror("calloc failed");
        xfree(msg_reply);
        return NULL;
    }

    req = (struct dt_req_malloc *)msg->buf;
    rsp = (struct dt_rsp_malloc*)(msg_reply->buf);
    if (msg->header.buf_size != sizeof(struct dt_req_malloc)) {
        rsp->low = 0;
        rsp->high = req->ssid;
    } else {
        memory_malloc(req, rsp);
    }

    return msg_reply;
}

static dt_message_t *build_free_reply(dt_message_t *msg)
{
    struct dt_rsp_free *rsp = NULL;
    struct dt_req_free *req = NULL;

    dt_message_t *msg_reply = xmalloc(sizeof(dt_message_t));
    if (!msg_reply) {
        pr_err("calloc failed");
        return NULL;
    }

    msg_reply->header.cmd = CMD_RSP_FREE;
    msg_reply->header.id = msg->header.id;
    msg_reply->header.buf_size = sizeof(struct dt_rsp_free);

    msg_reply->buf = xmalloc(msg_reply->header.buf_size);
    if (!msg_reply->buf) {
        perror("calloc failed");
        xfree(msg_reply);
        return NULL;
    }

    req = (struct dt_req_free *)msg->buf;
    rsp = (struct dt_rsp_free*)(msg_reply->buf);
    if (msg->header.buf_size != sizeof(struct dt_req_free)) {
        rsp->retval = -1;
    } else {
        memory_free(req, rsp);
    }

    return msg_reply;
}

static dt_message_t *build_memset_reply(dt_message_t *msg)
{
    struct dt_rsp_memset *rsp = NULL;
    struct dt_req_memset *req = NULL;

    dt_message_t *msg_reply = xmalloc(sizeof(dt_message_t));
    if (!msg_reply) {
        pr_err("calloc failed");
        return NULL;
    }

    msg_reply->header.cmd = CMD_RSP_MEMSET;
    msg_reply->header.id = msg->header.id;
    msg_reply->header.buf_size = sizeof(struct dt_rsp_memset);

    msg_reply->buf = xmalloc(msg_reply->header.buf_size);
    if (!msg_reply->buf) {
        perror("calloc failed");
        xfree(msg_reply);
        return NULL;
    }

    req = (struct dt_req_memset *)msg->buf;
    rsp = (struct dt_rsp_memset*)(msg_reply->buf);
    if (msg->header.buf_size != sizeof(struct dt_req_memset)) {
        rsp->retval = -1;
    } else {
        memory_memset(req, rsp);
    }

    return msg_reply;
}

static void memory_memcpyfrom(const struct dt_req_memcpyfrom *req,
        struct dt_rsp_memcpyfrom *rsp)
{
    int fd;
    void *addr;
    char path[128] = { 0 };

    snprintf(path, sizeof(path), "%s-%016" PRIx64, SHM_PREFIX, req->low);

    fd = shm_open(path, O_RDWR, 0666);
    if (fd == -1) {
        perror("shm_open failed");
        rsp->retval = -1;
        return;
    }
    addr = mmap(0, req->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        perror("mmap failed");
        close(fd);
        rsp->retval = -1;
        return;
    }
    close(fd);

    memcpy(rsp->data, addr + req->offset, req->len);
    rsp->retval = 0;

    munmap(addr, req->size);
}

static void memory_memcpyto(const struct dt_req_memcpyto *req,
        struct dt_rsp_memcpyto *rsp)
{
    int fd;
    void *addr;
    char path[128] = { 0 };

    snprintf(path, sizeof(path), "%s-%016" PRIx64, SHM_PREFIX, req->low);

    fd = shm_open(path, O_RDWR, 0666);
    if (fd == -1) {
        perror("shm_open failed");
        rsp->retval = -1;
        return;
    }
    addr = mmap(0, req->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        perror("mmap failed");
        close(fd);
        rsp->retval = -1;
        return;
    }
    close(fd);

    memcpy(addr + req->offset, req->data, req->len);
    rsp->retval = 0;

    munmap(addr, req->size);

}

static void memory_memcpy(const struct dt_req_memcpy *req,
        struct dt_rsp_memcpy *rsp)
{
    int fd;
    void *addr;
    dt_addr_t to = { 0 };
    char path[128] = { 0 };

    snprintf(path, sizeof(path), "%s-%016" PRIx64, SHM_PREFIX, req->from_low);

    fd = shm_open(path, O_RDWR, 0666);
    if (fd == -1) {
        perror("shm_open failed");
        rsp->retval = -1;
        return;
    }
    addr = mmap(0, req->from_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        perror("mmap failed");
        close(fd);
        rsp->retval = -1;
        return;
    }
    close(fd);

    to.low = req->to_low;
    to.high = req->to_high;
    to.offset = req->to_offset;
    to.size = req->to_size;
    if (dt_memcpy_to(&to, addr, req->len)) {
        rsp->retval = 0;
    } else {
        rsp->retval = -1;
    }

    munmap(addr, req->from_size);
}

static dt_message_t *build_memcpyfrom_reply(dt_message_t *msg)
{
    struct dt_req_memcpyfrom *req = (struct dt_req_memcpyfrom *)msg->buf;
    struct dt_rsp_memcpyfrom *rsp = NULL;

    dt_message_t *msg_reply = xmalloc(sizeof(dt_message_t));
    if (!msg_reply) {
        pr_err("calloc failed");
        return NULL;
    }

    msg_reply->header.cmd = CMD_RSP_MEMCPYFROM;
    msg_reply->header.id = msg->header.id;
    msg_reply->header.buf_size = offsetof(struct dt_rsp_memcpyfrom, data) + req->len;
    msg_reply->buf = xmalloc(sizeof(struct dt_rsp_memcpyfrom));
    if (!msg_reply->buf) {
        perror("calloc failed");
        xfree(msg_reply);
        return NULL;
    }
    rsp = (struct dt_rsp_memcpyfrom*)(msg_reply->buf);
    rsp->data = xmalloc(req->len);
    if (!rsp->data) {
        perror("calloc failed");
        xfree(msg_reply->buf);
        xfree(msg_reply);
        return NULL;
    }
    msg_reply->header.data_len = req->len;
    msg_reply->data = rsp->data;

    if (msg->header.buf_size != sizeof(struct dt_req_memcpyfrom)) {
        rsp->retval = -1;
    } else {
        memory_memcpyfrom(req, rsp);
    }

    return msg_reply;
}

static dt_message_t *build_memcpyto_reply(dt_message_t *msg)
{
    struct dt_req_memcpyto req = { 0 };
    size_t req_header_size = sizeof(req) - sizeof(req.data);
    struct dt_rsp_memcpyto *rsp = NULL;

    dt_message_t *msg_reply = xmalloc(sizeof(dt_message_t));
    if (!msg_reply) {
        pr_err("calloc failed");
        return NULL;
    }

    msg_reply->header.cmd = CMD_RSP_MEMCPYTO;
    msg_reply->header.id = msg->header.id;
    msg_reply->header.buf_size = sizeof(struct dt_rsp_memcpyto);
    msg_reply->buf = xmalloc(msg_reply->header.buf_size);
    if (!msg_reply->buf) {
        perror("calloc failed");
        xfree(msg_reply);
        return NULL;
    }
    rsp = (struct dt_rsp_memcpyto*)(msg_reply->buf);

    if (msg->header.buf_size < req_header_size) {
        rsp->retval = -1;
    } else {
        memcpy(&req, msg->buf, req_header_size);
        req.data = msg->buf + req_header_size;
        memory_memcpyto(&req, rsp);
    }

    return msg_reply;
}

static dt_message_t *build_memcpy_reply(dt_message_t *msg)
{
    struct dt_req_memcpy *req = (struct dt_req_memcpy *)msg->buf; ;
    struct dt_rsp_memcpy *rsp = NULL;

    dt_message_t *msg_reply = xmalloc(sizeof(dt_message_t));
    if (!msg_reply) {
        pr_err("calloc failed");
        return NULL;
    }

    msg_reply->header.cmd = CMD_RSP_MEMCPY;
    msg_reply->header.id = msg->header.id;
    msg_reply->header.buf_size = sizeof(struct dt_rsp_memcpy);
    msg_reply->buf = xmalloc(msg_reply->header.buf_size);
    if (!msg_reply->buf) {
        perror("calloc failed");
        xfree(msg_reply);
        return NULL;
    }
    rsp = (struct dt_rsp_memcpy *)(msg_reply->buf);

    if (msg->header.buf_size < sizeof(struct dt_req_memcpy)) {
        rsp->retval = -1;
    } else {
        memory_memcpy(req, rsp);
    }

    return msg_reply;
}

dt_message_t *process_memory_msg(dt_message_t *msg)
{
    dt_message_t *msg_reply = NULL;

    if (msg->header.cmd == CMD_REQ_MALLOC) {
        msg_reply = build_malloc_reply(msg);
    } else if (msg->header.cmd == CMD_REQ_FREE) {
        msg_reply = build_free_reply(msg);
    } else if (msg->header.cmd == CMD_REQ_MEMSET) {
        msg_reply = build_memset_reply(msg);
    } else if (msg->header.cmd == CMD_REQ_MEMCPYFROM) {
        msg_reply = build_memcpyfrom_reply(msg);
    } else if (msg->header.cmd == CMD_REQ_MEMCPYTO) {
        msg_reply = build_memcpyto_reply(msg);
    } else if (msg->header.cmd == CMD_REQ_MEMCPY) {
        msg_reply = build_memcpy_reply(msg);
    }

    return msg_reply;
}

