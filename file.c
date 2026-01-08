#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <arpa/inet.h>

#include "util.h"
#include "log.h"
#include "md5.h"
#include "file.h"

static int file_calculate_md5(const char *filename, char *md5sum)
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

static void file_stat(const struct dt_req_filestat *req, struct dt_rsp_filestat *rsp)
{
    memset(rsp, 0, sizeof(struct dt_rsp_filestat));

    if (req->path[0] == '\0') {
        rsp->retval = -EINVAL;  // Invalid parameter
        return;
    }

    // Check if file exists
    struct stat st;
    if (stat(req->path, &st) == -1) {
        rsp->retval = -1;
        if (errno == ENOENT || errno == EACCES || errno == ENOTDIR) {
            rsp->retval = -errno;
        }
        return;
    }
    rsp->size = st.st_size;
    rsp->retval = 0;

    mode_t mode = st.st_mode;

    // File type
    if (S_ISREG(mode))  rsp->type = '-';
    else if (S_ISDIR(mode)) rsp->type = 'd';
    else if (S_ISCHR(mode)) rsp->type = 'c';
    else if (S_ISBLK(mode)) rsp->type = 'b';
    else if (S_ISFIFO(mode)) rsp->type = 'p';
    else if (S_ISLNK(mode)) rsp->type = 'l';
    else if (S_ISSOCK(mode)) rsp->type = 's';
    else rsp->type = '?';

    // Permissions (lower 12 bits)
    rsp->mode = mode & 0777;
}

static void file_hash(const struct dt_req_filehash *req, struct dt_rsp_filehash *rsp)
{
    memset(rsp, 0, sizeof(struct dt_rsp_filehash));

    if (req->path[0] == '\0') {
        rsp->retval = -EINVAL;  // Invalid parameter
        return;
    }

    // Check if file exists
    struct stat st;
    if (stat(req->path, &st) == -1) {
        rsp->retval = -1;
        if (errno == ENOENT || errno == EACCES || errno == ENOTDIR) {
            rsp->retval = -errno;
        }
        return;
    }

    // Check if it's a regular file
    if (!S_ISREG(st.st_mode)) {
        rsp->retval = -1;
        return;
    }

    int ret = file_calculate_md5(req->path, rsp->md5sum);
    if (ret != 0) {
        rsp->retval = -1;
        return;
    }
    rsp->retval = 0;
}

static int64_t file_write(const struct dt_req_filewrite *req)
{
    if (req == NULL) {
        pr_err("Error: Request is NULL");
        return -1;
    }

    if (strlen(req->path) == 0) {
        pr_err("Error: File path is empty");
        return -1;
    }

    // Open file in read-write mode, create if doesn't exist
    // O_CREAT: Create file if it doesn't exist
    // O_RDWR: Read-write mode
    int fd = open(req->path, O_CREAT | O_RDWR, 0644);
    if (fd == -1) {
        pr_err("Error: Cannot open file %s: %s", req->path, strerror(errno));
        return -1;
    }

    // Seek to specified offset
    if (lseek(fd, req->offset, SEEK_SET) == -1) {
        pr_err("Error: Cannot seek to offset %lu: %s", req->offset, strerror(errno));
        close(fd);
        return -1;
    }

    // Write data
    ssize_t bytes_written = xwrite(fd, req->data, req->len);
    if (bytes_written == -1) {
        pr_err("Error: Cannot write to file: %s", strerror(errno));
        close(fd);
        return -1;
    }

    // Check if all data was written
    if ((uint64_t)bytes_written != req->len) {
        pr_err("Warning: Partial write: %zd of %lu bytes written",
                bytes_written, req->len);
    }

    // Sync file data to disk
    if (fsync(fd) == -1) {
        pr_err("Warning: fsync failed: %s", strerror(errno));
    }

    close(fd);
    return (int64_t)bytes_written ;
}

static int64_t file_read(const struct dt_req_fileread *req, char *data, size_t size)
{
    if (req == NULL) {
        pr_err("Error: Request is NULL");
        return -1;
    }

    if (strlen(req->path) == 0) {
        pr_err("Error: File path is empty");
        return -1;
    }

    // Open file in read-write mode
    // O_RDWR: Read-write mode
    int fd = open(req->path, O_RDWR, 0644);
    if (fd == -1) {
        pr_err("Error: Cannot open file %s: %s", req->path, strerror(errno));
        return -1;
    }

    // Seek to specified offset
    if (lseek(fd, req->offset, SEEK_SET) == -1) {
        pr_err("Error: Cannot seek to offset %lu: %s", req->offset, strerror(errno));
        close(fd);
        return -1;
    }

    // Read data
    size_t bytes_read = xread(fd, data, size);
    // Check if data is complete
    if (bytes_read != size) {
        pr_info("Partial read: %zd of %lu bytes read", bytes_read, size);
    }

    close(fd);
    return bytes_read;
}

static void file_remove(const struct dt_req_fileremove *req, struct dt_rsp_fileremove *rsp)
{
    memset(rsp, 0, sizeof(struct dt_rsp_fileremove));

    if (req->path[0] == '\0') {
        rsp->retval = -1;
        return;
    }

    // Check if file exists
    struct stat st;
    if (stat(req->path, &st) == -1) {
        rsp->retval = -ENOENT;
        return;
    }

    // Check if it's a regular file
    if (!S_ISREG(st.st_mode)) {
        rsp->retval = -1;
        return;
    }
    rsp->retval = unlink(req->path);
}

static void file_chmod(const struct dt_req_filechmod *req, struct dt_rsp_filechmod *rsp)
{
    memset(rsp, 0, sizeof(struct dt_rsp_filechmod));

    if (req->path[0] == '\0') {
        rsp->retval = -1;
        return;
    }

    // Check if file exists
    struct stat st;
    if (stat(req->path, &st) == -1) {
        rsp->retval = -ENOENT;
        return;
    }

    // Check if current permissions are already the target permissions
    if ((st.st_mode & 0777) == req->mode) {
        rsp->retval = 0;
        return;
    }

    // Check if it's a regular file
    if (!S_ISREG(st.st_mode)) {
        rsp->retval = -1;
        return;
    }
    rsp->retval = chmod(req->path, req->mode);
}

static dt_message_t *build_open_reply(dt_message_t *msg)
{
    struct dt_req_open *req = (struct dt_req_open *)msg->buf;
    size_t req_header_size = sizeof(struct dt_req_open);
    struct dt_rsp_open *rsp = NULL;

    dt_message_t *msg_reply = xmalloc(sizeof(dt_message_t));
    if (!msg_reply) {
        pr_err("malloc failed");
        return NULL;
    }

    msg_reply->header.cmd = CMD_RSP_OPEN;
    msg_reply->header.id = msg->header.id;
    msg_reply->header.buf_size = sizeof(struct dt_rsp_open);

    msg_reply->buf = xmalloc(sizeof(struct dt_rsp_open));
    if (!msg_reply->buf) {
        pr_err("malloc failed");
        xfree(msg_reply);
        return NULL;
    }
    rsp = (struct dt_rsp_open *)msg_reply->buf;

    if (msg->header.buf_size == req_header_size) {
        rsp->fd = open(req->path, req->oflag, req->mode);
    } else {
        rsp->fd = -1;
    }

    return msg_reply;
}

static dt_message_t *build_close_reply(dt_message_t *msg)
{
    struct dt_req_close *req = (struct dt_req_close *)msg->buf;
    size_t req_header_size = sizeof(struct dt_req_close);
    struct dt_rsp_close *rsp = NULL;

    dt_message_t *msg_reply = xmalloc(sizeof(dt_message_t));
    if (!msg_reply) {
        pr_err("malloc failed");
        return NULL;
    }

    msg_reply->header.cmd = CMD_RSP_CLOSE;
    msg_reply->header.id = msg->header.id;
    msg_reply->header.buf_size = sizeof(struct dt_rsp_close);

    msg_reply->buf = xmalloc(sizeof(struct dt_rsp_close));
    if (!msg_reply->buf) {
        pr_err("malloc failed");
        xfree(msg_reply);
        return NULL;
    }
    rsp = (struct dt_rsp_close *)msg_reply->buf;

    if (msg->header.buf_size < req_header_size) {
        rsp->retval = close(req->fd);
    }

    return msg_reply;
}

static dt_message_t *build_read_reply(dt_message_t *msg)
{
    struct dt_req_read *req = (struct dt_req_read *)msg->buf;
    size_t req_header_size = sizeof(struct dt_req_read);
    struct dt_rsp_read *rsp = NULL;

    dt_message_t *msg_reply = xmalloc(sizeof(dt_message_t));
    if (!msg_reply) {
        pr_err("malloc failed");
        return NULL;
    }

    msg_reply->header.cmd = CMD_RSP_READ;
    msg_reply->header.id = msg->header.id;
    msg_reply->header.buf_size = offsetof(struct dt_rsp_read, data);

    msg_reply->buf = xmalloc(sizeof(struct dt_rsp_read));
    if (!msg_reply->buf) {
        pr_err("malloc failed");
        xfree(msg_reply);
        return NULL;
    }
    rsp = (struct dt_rsp_read *)msg_reply->buf;

    if (msg->header.buf_size < req_header_size) {
        rsp->len = 0;
    } else {
        msg_reply->data = (char *)xmalloc(msg_reply->header.data_len);
        if (msg_reply->data) {
            rsp->data = msg_reply->data;
            rsp->len = xread(req->fd, rsp->data, msg_reply->header.data_len);
        } else {
            msg_reply->header.data_len = 0;
            rsp->len = 0;
            pr_err("malloc failed");
        }
        msg_reply->header.buf_size += msg_reply->header.data_len;
    }

    return msg_reply;
}

static dt_message_t *build_write_reply(dt_message_t *msg)
{
    struct dt_req_write req = { 0 };
    size_t req_header_size = sizeof(req) - sizeof(req.data);
    struct dt_rsp_write *rsp = NULL;

    dt_message_t *msg_reply = xmalloc(sizeof(dt_message_t));
    if (!msg_reply) {
        pr_err("calloc failed");
        return NULL;
    }

    msg_reply->header.cmd = CMD_RSP_WRITE;
    msg_reply->header.id = msg->header.id;
    msg_reply->header.buf_size = sizeof(struct dt_rsp_write);

    msg_reply->buf = xmalloc(msg_reply->header.buf_size);
    if (!msg_reply->buf) {
        perror("calloc failed");
        xfree(msg_reply);
        return NULL;
    }

    rsp = (struct dt_rsp_write*)(msg_reply->buf);

    if (msg->header.buf_size < req_header_size) {
        rsp->len = 0;
    } else {
        memcpy(&req, msg->buf, req_header_size);
        req.data = msg->buf + req_header_size;
        rsp->len = xwrite(req.fd, req.data, req.len);
    }

    return msg_reply;
}

static dt_message_t *build_file_stat_reply(dt_message_t *msg)
{
    struct dt_rsp_filestat *rsp = NULL;

    dt_message_t *msg_reply = xmalloc(sizeof(dt_message_t));
    if (!msg_reply) {
        pr_err("calloc failed");
        return NULL;
    }

    msg_reply->header.cmd = CMD_RSP_FILESTAT;
    msg_reply->header.id = msg->header.id;
    msg_reply->header.buf_size = sizeof(struct dt_rsp_filestat);

    msg_reply->buf = xmalloc(msg_reply->header.buf_size);
    if (!msg_reply->buf) {
        perror("calloc failed");
        xfree(msg_reply);
        return NULL;
    }

    rsp = (struct dt_rsp_filestat*)(msg_reply->buf);

    if (msg->header.buf_size < sizeof(struct dt_req_filestat)) {
        rsp->retval = -1;
    } else {
        file_stat((struct dt_req_filestat *)msg->buf, rsp);
    }

    return msg_reply;
}


static dt_message_t *build_file_hash_reply(dt_message_t *msg)
{
    struct dt_rsp_filehash *rsp = NULL;

    dt_message_t *msg_reply = xmalloc(sizeof(dt_message_t));
    if (!msg_reply) {
        pr_err("calloc failed");
        return NULL;
    }

    msg_reply->header.cmd = CMD_RSP_FILEHASH;
    msg_reply->header.id = msg->header.id;
    msg_reply->header.buf_size = sizeof(struct dt_rsp_filehash);

    msg_reply->buf = xmalloc(msg_reply->header.buf_size);
    if (!msg_reply->buf) {
        perror("calloc failed");
        xfree(msg_reply);
        return NULL;
    }

    rsp = (struct dt_rsp_filehash*)(msg_reply->buf);

    if (msg->header.buf_size < sizeof(struct dt_req_filehash)) {
        rsp->retval = -1;
    } else {
        file_hash((struct dt_req_filehash *)msg->buf, rsp);
    }

    return msg_reply;
}

static dt_message_t *build_file_write_reply(dt_message_t *msg)
{
    struct dt_req_filewrite req = { 0 };
    size_t req_header_size = sizeof(req) - sizeof(req.data);
    struct dt_rsp_filewrite *rsp = NULL;

    dt_message_t *msg_reply = xmalloc(sizeof(dt_message_t));
    if (!msg_reply) {
        pr_err("calloc failed");
        return NULL;
    }

    msg_reply->header.cmd = CMD_RSP_FILEWRITE;
    msg_reply->header.id = msg->header.id;
    msg_reply->header.buf_size = sizeof(struct dt_rsp_filewrite);

    msg_reply->buf = xmalloc(msg_reply->header.buf_size);
    if (!msg_reply->buf) {
        perror("calloc failed");
        xfree(msg_reply);
        return NULL;
    }

    rsp = (struct dt_rsp_filewrite*)(msg_reply->buf);

    if (msg->header.buf_size < req_header_size) {
        rsp->len = 0;
    } else {
        memcpy(&req, msg->buf, req_header_size);
        req.data = msg->buf + req_header_size;
        rsp->len = file_write(&req);
    }

    return msg_reply;
}

static dt_message_t *build_file_read_reply(dt_message_t *msg)
{
    struct dt_req_fileread *req = (struct dt_req_fileread *)msg->buf;
    size_t req_header_size = sizeof(struct dt_req_fileread);
    struct dt_rsp_fileread *rsp = NULL;
    int64_t file_size;

    dt_message_t *msg_reply = xmalloc(sizeof(dt_message_t));
    if (!msg_reply) {
        pr_err("malloc failed");
        return NULL;
    }

    msg_reply->header.cmd = CMD_RSP_FILEREAD;
    msg_reply->header.id = msg->header.id;
    msg_reply->header.buf_size = offsetof(struct dt_rsp_fileread, data);

    msg_reply->buf = xmalloc(sizeof(struct dt_rsp_fileread));
    if (!msg_reply->buf) {
        pr_err("malloc failed");
        xfree(msg_reply);
        return NULL;
    }
    rsp = (struct dt_rsp_fileread *)msg_reply->buf;

    if (msg->header.buf_size < req_header_size) {
        rsp->len = 0;
    } else {
        file_size = xfile_size(req->path);
        if (file_size <= 0 || (uint64_t)file_size <= req->offset) {
            rsp->len = 0;
            pr_err("file size %ld or offset %ld  invalid", file_size, req->offset);
        } else {
            msg_reply->header.data_len = min(req->len, (int64_t)(file_size - req->offset));
            msg_reply->data = (char *)xmalloc(msg_reply->header.data_len);
            if (msg_reply->data) {
                rsp->data = msg_reply->data;
                rsp->len = file_read(req, rsp->data, msg_reply->header.data_len);
            } else {
                msg_reply->header.data_len = 0;
                rsp->len = 0;
                pr_err("malloc failed");
            }
            msg_reply->header.buf_size += msg_reply->header.data_len;
        }
    }

    return msg_reply;
}

static dt_message_t *build_file_remove_reply(dt_message_t *msg)
{
    struct dt_rsp_fileremove *rsp = NULL;

    dt_message_t *msg_reply = xmalloc(sizeof(dt_message_t));
    if (!msg_reply) {
        pr_err("calloc failed");
        return NULL;
    }

    msg_reply->header.cmd = CMD_RSP_FILEREMOVE;
    msg_reply->header.id = msg->header.id;
    msg_reply->header.buf_size = sizeof(struct dt_rsp_fileremove);

    msg_reply->buf = xmalloc(msg_reply->header.buf_size);
    if (!msg_reply->buf) {
        perror("calloc failed");
        xfree(msg_reply);
        return NULL;
    }

    rsp = (struct dt_rsp_fileremove*)(msg_reply->buf);

    if (msg->header.buf_size < sizeof(struct dt_req_fileremove)) {
        rsp->retval = -1;
    } else {
        file_remove((struct dt_req_fileremove *)msg->buf, rsp);
    }

    return msg_reply;
}

static dt_message_t *build_file_chmod_reply(dt_message_t *msg)
{
    struct dt_rsp_filechmod *rsp = NULL;

    dt_message_t *msg_reply = xmalloc(sizeof(dt_message_t));
    if (!msg_reply) {
        pr_err("calloc failed");
        return NULL;
    }

    msg_reply->header.cmd = CMD_RSP_FILECHMOD;
    msg_reply->header.id = msg->header.id;
    msg_reply->header.buf_size = sizeof(struct dt_rsp_filechmod);

    msg_reply->buf = xmalloc(msg_reply->header.buf_size);
    if (!msg_reply->buf) {
        perror("calloc failed");
        xfree(msg_reply);
        return NULL;
    }

    rsp = (struct dt_rsp_filechmod*)(msg_reply->buf);

    if (msg->header.buf_size < sizeof(struct dt_req_filechmod)) {
        rsp->retval = -1;
    } else {
        file_chmod((struct dt_req_filechmod *)msg->buf, rsp);
    }

    return msg_reply;
}

dt_message_t *process_file_msg(dt_message_t *msg)
{
    dt_message_t *msg_reply = NULL;

    if (msg->header.cmd == CMD_REQ_OPEN) {
        msg_reply = build_open_reply(msg);
    } else if (msg->header.cmd == CMD_REQ_CLOSE) {
        msg_reply = build_close_reply(msg);
    } else if (msg->header.cmd == CMD_REQ_READ) {
        msg_reply = build_read_reply(msg);
    } else if (msg->header.cmd == CMD_REQ_WRITE) {
        msg_reply = build_write_reply(msg);
    } else if (msg->header.cmd == CMD_REQ_FILESTAT) {
        msg_reply = build_file_stat_reply(msg);
    } else if (msg->header.cmd == CMD_REQ_FILEHASH) {
        msg_reply = build_file_hash_reply(msg);
    } else if (msg->header.cmd == CMD_REQ_FILEWRITE) {
        msg_reply = build_file_write_reply(msg);
    } else if (msg->header.cmd == CMD_REQ_FILEREAD) {
        msg_reply = build_file_read_reply(msg);
    } else if (msg->header.cmd == CMD_REQ_FILEREMOVE) {
        msg_reply = build_file_remove_reply(msg);
    } else if (msg->header.cmd == CMD_REQ_FILECHMOD) {
        msg_reply = build_file_chmod_reply(msg);
    }

    return msg_reply;
}

