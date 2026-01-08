#ifndef __TRANSFER_H__
#define __TRANSFER_H__

#include <stdint.h>

#define TMP_DIR    "/tmp/dtts"
#define SHM_PREFIX "/dtts"

#define TRANS_PORT 15943

typedef struct {
    char ip[16];
    char hostname[64];
    uint64_t ssid;    //  Service set identifier
    float avail_load;
} dt_node_t;

#define CMD_NODE_BASE   (0x0100 << 0)
#define CMD_TASK_BASE   (0x0100 << 1)
#define CMD_FILE_BASE   (0x0100 << 2)
#define CMD_MEMORY_BASE (0x0100 << 3)

enum {
    CMD_REQ_PING         = CMD_NODE_BASE + 0x00,
    CMD_RSP_PING         = CMD_NODE_BASE + 0x01,
    CMD_REQ_LOGLEVEL     = CMD_NODE_BASE + 0x02,
    CMD_RSP_LOGLEVEL     = CMD_NODE_BASE + 0x03,

    CMD_REQ_REGISTER     = CMD_TASK_BASE + 0x00,
    CMD_RSP_REGISTER     = CMD_TASK_BASE + 0x01,
    CMD_REQ_APPEND_ARGS  = CMD_TASK_BASE + 0x02,
    CMD_RSP_APPEND_ARGS  = CMD_TASK_BASE + 0x03,
    CMD_REQ_APPEND_RET   = CMD_TASK_BASE + 0x04,
    CMD_RSP_APPEND_RET   = CMD_TASK_BASE + 0x05,
    CMD_REQ_START        = CMD_TASK_BASE + 0x06,
    CMD_RSP_START        = CMD_TASK_BASE + 0x07,
    CMD_REQ_WAIT         = CMD_TASK_BASE + 0x08,
    CMD_RSP_WAIT         = CMD_TASK_BASE + 0x09,

    CMD_REQ_OPEN         = CMD_FILE_BASE + 0x00,
    CMD_RSP_OPEN         = CMD_FILE_BASE + 0x01,
    CMD_REQ_READ         = CMD_FILE_BASE + 0x02,
    CMD_RSP_READ         = CMD_FILE_BASE + 0x03,
    CMD_REQ_WRITE        = CMD_FILE_BASE + 0x04,
    CMD_RSP_WRITE        = CMD_FILE_BASE + 0x05,
    CMD_REQ_CLOSE        = CMD_FILE_BASE + 0x06,
    CMD_RSP_CLOSE        = CMD_FILE_BASE + 0x07,
    CMD_REQ_FILESTAT     = CMD_FILE_BASE + 0x50,
    CMD_RSP_FILESTAT     = CMD_FILE_BASE + 0x51,
    CMD_REQ_FILEHASH     = CMD_FILE_BASE + 0x52,
    CMD_RSP_FILEHASH     = CMD_FILE_BASE + 0x53,
    CMD_REQ_FILEWRITE    = CMD_FILE_BASE + 0x54,
    CMD_RSP_FILEWRITE    = CMD_FILE_BASE + 0x55,
    CMD_REQ_FILEREAD     = CMD_FILE_BASE + 0x56,
    CMD_RSP_FILEREAD     = CMD_FILE_BASE + 0x57,
    CMD_REQ_FILEREMOVE   = CMD_FILE_BASE + 0x58,
    CMD_RSP_FILEREMOVE   = CMD_FILE_BASE + 0x59,
    CMD_REQ_FILECHMOD    = CMD_FILE_BASE + 0x5a,
    CMD_RSP_FILECHMOD    = CMD_FILE_BASE + 0x5b,

    CMD_REQ_MALLOC       = CMD_MEMORY_BASE + 0x00,
    CMD_RSP_MALLOC       = CMD_MEMORY_BASE + 0x01,
    CMD_REQ_FREE         = CMD_MEMORY_BASE + 0x02,
    CMD_RSP_FREE         = CMD_MEMORY_BASE + 0x03,
    CMD_REQ_MEMSET       = CMD_MEMORY_BASE + 0x04,
    CMD_RSP_MEMSET       = CMD_MEMORY_BASE + 0x05,
    CMD_REQ_MEMCPYFROM   = CMD_MEMORY_BASE + 0x06,
    CMD_RSP_MEMCPYFROM   = CMD_MEMORY_BASE + 0x07,
    CMD_REQ_MEMCPYTO     = CMD_MEMORY_BASE + 0x08,
    CMD_RSP_MEMCPYTO     = CMD_MEMORY_BASE + 0x09,
    CMD_REQ_MEMCPY       = CMD_MEMORY_BASE + 0x0a,
    CMD_RSP_MEMCPY       = CMD_MEMORY_BASE + 0x0b,
};

struct dt_req_ping {
    char data[4];
};

struct dt_rsp_ping {
    char data[4];
};

struct dt_req_loglevel {
    int32_t operation;  // 0=get 1=set
    int32_t loglevel;
};

struct dt_rsp_loglevel {
    int32_t cur_loglevel;
    int32_t old_loglevel;  // only for setting
    int32_t retval;
};

struct dt_task_args {
    uint64_t len;
    char data[];
};

struct dt_task_ret {
    uint64_t len;
    char data[];
};

struct dt_cmd_ret {
    uint64_t outlen;
    uint64_t errlen;
    uint64_t result;
    char data[];
};

struct dt_req_open {
    char path[127];
    char reuse;    // default: 1
    uint32_t oflag;
    uint32_t mode;
};

struct dt_rsp_open {
    int64_t fd;
};

struct dt_req_close {
    int64_t fd;
};

struct dt_rsp_close {
    int64_t retval;
};

struct dt_req_read {
    uint64_t fd;
    int64_t len;
};

struct dt_rsp_read {
    int64_t len;
    char *data;
};

struct dt_req_write {
    uint64_t fd;
    uint64_t len;
    char *data;
};

struct dt_rsp_write {
    int64_t len;
};

struct dt_req_filestat {
    char path[128];
};

struct dt_rsp_filestat {
    int64_t retval;
    uint64_t size;
    uint16_t mode;
    char type;
};

struct dt_req_filehash {
    char path[128];
};

struct dt_rsp_filehash {
    int64_t retval;
    char md5sum[40];
};

struct dt_req_filewrite {
    char path[128];
    uint64_t offset;
    uint64_t len;
    char *data;
};

struct dt_rsp_filewrite {
    int64_t len;
};

struct dt_req_fileread {
    char path[128];
    uint64_t offset;
    int64_t len;
};

struct dt_rsp_fileread {
    int64_t len;
    char *data;
};

struct dt_req_fileremove {
    char path[128];
};

struct dt_rsp_fileremove {
    int retval;
};

struct dt_req_filechmod {
    char path[128];
    uint16_t mode;
};

struct dt_rsp_filechmod {
    int retval;
};

struct dt_req_malloc {
    uint64_t ssid;
    uint64_t size;
};

struct dt_rsp_malloc {
    uint64_t low;
    uint64_t high;
};

struct dt_req_free {
    uint64_t low;
    uint64_t high;
};

struct dt_rsp_free {
    int retval;
};

struct dt_req_memset {
    uint64_t low;
    uint64_t high;
    uint64_t offset;
    uint64_t size;
    uint64_t len;
    uint8_t val;
};

struct dt_rsp_memset {
    int retval;
};

struct dt_req_memcpyfrom {
    uint64_t low;
    uint64_t high;
    uint64_t offset;
    uint64_t size;
    uint64_t len;
};

struct dt_rsp_memcpyfrom {
    int retval;
    char *data;
};

struct dt_req_memcpyto {
    uint64_t low;
    uint64_t high;
    uint64_t offset;
    uint64_t size;
    uint64_t len;
    char *data;
};

struct dt_rsp_memcpyto {
    int retval;
};

struct dt_req_memcpy {
    uint64_t from_low;
    uint64_t from_high;
    uint64_t from_offset;
    uint64_t from_size;

    uint64_t to_low;
    uint64_t to_high;
    uint64_t to_offset;
    uint64_t to_size;

    uint64_t len;
};

struct dt_rsp_memcpy {
    int retval;
};

struct dt_message_header {
    uint16_t version;
    int16_t status;
    uint32_t cmd;
    int64_t  id;
    uint64_t buf_size;
    uint64_t data_len;
    uint8_t reserved[14];
    uint16_t crc;
} __attribute__((packed));

typedef struct {
    struct dt_message_header header;
    char *buf;
    char *data;
} dt_message_t;

int client_send(dt_node_t *node, dt_message_t *msg, dt_message_t *reply);

#endif
