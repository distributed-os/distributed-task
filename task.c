#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <libgen.h>
#include <poll.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "util.h"
#include "log.h"
#include "list.h"
#include "dtt/transfer.h"

struct itask_reader_arg {
    int fd_out;
    int fd_err;
    struct dt_cmd_ret *cmdret;
};

struct itask_desc {
    char type;
    char *path;
    char *name;
};

enum task_state {
    TASK_READY,
    TASK_RUNNING,
    TASK_FINISHED
};
struct itask {
    int64_t id;
    enum task_state state;
    char *path;
    struct itask_desc *desc;
    pid_t pid;
    uint64_t shmkey[2];
    struct dt_task_args *args;
    struct dt_task_ret *ret;
    struct dt_cmd_ret *cmdret;
    struct list_head list;
};

LIST_HEAD(itask_list);
static pthread_mutex_t itask_lock = PTHREAD_MUTEX_INITIALIZER;

static void itask_install(struct itask *it)
{
    INIT_LIST_HEAD(&it->list);
    pthread_mutex_lock(&itask_lock);
    list_add_tail(&it->list, &itask_list);
    pthread_mutex_unlock(&itask_lock);
}

static struct itask *itask_lookup(int64_t id)
{
    struct list_head *pos;
    struct itask *entry;

    pthread_mutex_lock(&itask_lock);
    list_for_each(pos, &itask_list) {
        entry = list_entry(pos, struct itask, list);
        if (entry && entry->id == id) {
            pthread_mutex_unlock(&itask_lock);
            return entry;
        }
    }
    pthread_mutex_unlock(&itask_lock);
    return NULL;
}

static void itask_remove(int64_t id)
{
    struct list_head *pos;
    struct itask *entry;
    struct itask *find = NULL;

    pthread_mutex_lock(&itask_lock);
    list_for_each(pos, &itask_list) {
        entry = list_entry(pos, struct itask, list);
        if (entry && entry->id == id) {
            find = entry;
            break;
        }
    }
    if (find) {
        list_del(&find->list);
    }
    pthread_mutex_unlock(&itask_lock);
}

static struct itask_desc *itask_parse(const char *s) {
    struct itask_desc *its = (struct itask_desc *)calloc(1, sizeof(struct itask_desc));
    char *token;
    char str_copy[128] = {};
    strncpy(str_copy, s, sizeof(str_copy) - 1);

    token = strtok(str_copy, ":");
    if (token != NULL) {
        its->type = token[0];
    }

    token = strtok(NULL, ":");
    if (token != NULL) {
        its->path = strdup(token);
    }

    token = strtok(NULL, ":");
    if (token != NULL) {
        its->name = strdup(token);
    }

    return its;
}

static int itask_register(uint64_t id, const char *path, uint64_t size)
{
    struct itask *it = (struct itask *)xmalloc(sizeof(struct itask));
    it->id = id;
    it->state = TASK_READY;
    it->path = (char *)xmalloc(size + 1);
    strncpy(it->path, path, size);
    it->desc = itask_parse(path);

    itask_install(it);
    return 0;
}

static int itask_append_args(uint64_t id, const void *buf, uint64_t size)
{
    struct dt_task_args *args = (struct dt_task_args *)buf;
    struct itask *it = itask_lookup(id);
    char path[64];
    uint64_t shm_key;
    size_t shm_size;
    void *shm_ptr;
    int fd;

    if (it && !it->args) {
        /*
         * key_t key = ftok("/tmp", (int)id % 100);
         * if (key == -1) {
         *     pe_err("error ftok args: %s\n", strerror(errno));
         *     return -1;
         * }
         */
        shm_key = id + 0;
        shm_size = args->len + sizeof(struct dt_task_args);
        if (shm_size != size) {
            pr_err("error args shm size: %lu %lu", shm_size, size);
            return -1;
        }
        do {
            shm_key++;
            memset(path, 0, sizeof(path));
            snprintf(path, sizeof(path), "%s-%016" PRIx64, SHM_PREFIX, shm_key);
            fd = shm_open(path, O_CREAT | O_RDWR, 0666);
            if (shm_key - id > 100) {
                pr_err("error shm_open args: %d %s", errno, strerror(errno));
                return -1;
            }
        } while (fd == -1 || fd == EINVAL);

        if (ftruncate(fd, shm_size) == -1) {
            close(fd);
            shm_unlink(path);
            pr_err("error ftruncate args: %d %s", errno, strerror(errno));
            return -1;
        }

        shm_ptr = mmap(0, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);   ;
        if (shm_ptr == (void *)-1) {
            close(fd);
            shm_unlink(path);
            pr_err("error mmap args: %d %s", errno, strerror(errno));
            return -1;
        }
        close(fd);

        it->shmkey[0] = shm_key;
        it->args = (struct dt_task_args *)shm_ptr;
        it->args->len = args->len;
        memcpy(it->args->data, args->data, args->len);
        return 0;
    }

    return -1;
}

static int itask_append_ret(uint64_t id, const void *buf)
{
    struct dt_task_ret *ret = (struct dt_task_ret *)buf;
    struct dt_cmd_ret *cmdret = (struct dt_cmd_ret *)buf;
    struct itask *it = itask_lookup(id);
    char path[64];
    uint64_t shm_key;
    size_t shm_size;
    void *shm_ptr;
    int fd;

    if (it && !it->ret) {
        /*
         * key_t key = ftok("/tmp", (int)id % 100);
         * if (key == -1) {
         *     pr_err("error ftok ret: %s", strerror(errno));
         *     return -1;
         * }
         */
        shm_key = id + 1;
        if (it->desc->type == 'C') {
            shm_size = cmdret->outlen + cmdret->errlen + sizeof(struct dt_cmd_ret);
        } else {
            shm_size = ret->len + sizeof(struct dt_task_ret);
        }
        do {
            shm_key++;
            memset(path, 0, sizeof(path));
            snprintf(path, sizeof(path), "%s-%016" PRIx64, SHM_PREFIX, shm_key);
            fd = shm_open(path, O_CREAT | O_RDWR, 0666);
            if (shm_key - id > 100) {
                pr_err("error shm_open ret: %d %s", errno, strerror(errno));
                return -1;
            }
        } while (fd == -1 || fd == EINVAL);

        if (ftruncate(fd, shm_size) == -1) {
            close(fd);
            shm_unlink(path);
            pr_err("error ftruncate ret: %d %s", errno, strerror(errno));
            return -1;
        }

        shm_ptr = mmap(0, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);   ;
        if (shm_ptr == (void *)-1) {
            close(fd);
            shm_unlink(path);
            pr_err("error mmap ret: %d %s", errno, strerror(errno));
            return -1;
        }
        close(fd);

        it->shmkey[1] = shm_key;
        if (it->desc->type == 'C') {
            it->cmdret = (struct dt_cmd_ret *)shm_ptr;
            it->cmdret->outlen = cmdret->outlen;
            it->cmdret->errlen = cmdret->errlen;
        } else {
            it->ret = (struct dt_task_ret *)shm_ptr;
            it->ret->len = ret->len;
        }

        return 0;
    }

    return -1;
}

static void *itask_reader_thread(void *arg)
{
    struct itask_reader_arg *p = (struct itask_reader_arg *)arg;
    struct pollfd fds[2];
    int running = 1;
    const size_t buf_size = 4096;
    size_t out_size = 0;
    size_t err_size = 0;
    char *buf = malloc(buf_size);

    fds[0].fd = p->fd_out;
    fds[0].events = POLLIN;
    fds[1].fd = p->fd_err;
    fds[1].events = POLLIN;

    while (running) {
        int ret = poll(fds, 2, 5000);  // 5-second timeout to prevent deadlock
        if (ret == 0) continue;        // Timeout, continue polling
        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (fds[0].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t n = read(p->fd_out, buf, buf_size - 1);
            if (n > 0) {
                buf[n] = '\0';
                if (p->cmdret) {
                    memcpy(p->cmdret->data + out_size, buf,
                            min(n, (ssize_t)(p->cmdret->outlen - out_size)));
                    out_size += n;
                } else {
                    fprintf(stdout, "%s", buf);
                    fflush(stdout);
                }
            } else if (n == 0 || (n < 0 && errno != EINTR && errno != EAGAIN)) {
                fds[0].fd = -1;   // Mark as closed
                close(p->fd_out);
            }
        }

        if (fds[1].revents & (POLLIN | POLLHUP | POLLERR)) {
            ssize_t n = read(p->fd_err, buf, buf_size - 1);
            if (n > 0) {
                buf[n] = '\0';
                if (p->cmdret) {
                    memcpy(p->cmdret->data + p->cmdret->outlen + err_size, buf,
                            min(n, (ssize_t)(p->cmdret->errlen - err_size)));
                    err_size += n;
                } else {
                    fprintf(stderr, "%s", buf);
                    fflush(stderr);
                }
            } else if (n == 0 || (n < 0 && errno != EINTR && errno != EAGAIN)) {
                fds[1].fd = -1;
                close(p->fd_err);
            }
        }

        // Both fds are closed, exit thread
        if (fds[0].fd == -1 && fds[1].fd == -1)
            running = 0;
    }

    // Ensure both fds are closed
    if (fds[0].fd >= 0) close(p->fd_out);
    if (fds[1].fd >= 0) close(p->fd_err);

    free(p);
    free(buf);
    return NULL;
}

static int itask_start(uint64_t id)
{
    struct itask *it = itask_lookup(id);
    if (!it)
        return -1;

    char env_task[64] = {};
    char env_shmkey0[64] = {};
    char env_shmkey1[64] = {};
    int stdout_pipe[2];
    int stderr_pipe[2];
    char *argv[2] = { 0 };
    char *envp[4] = { 0 };

    if (pipe(stdout_pipe) == -1 || pipe(stderr_pipe) == -1) {
        pr_err("pipe failed: %s", strerror(errno));
        goto cleanup_pipe;
    }

    argv[0] = basename(it->desc->path);
    sprintf(env_task, "DT_ENV_TASK=%s", it->desc->name);
    envp[0] = env_task;

    if (it->shmkey[0] > 0) {
        sprintf(env_shmkey0, "DT_ENV_SHMKEY0=%016" PRIx64, it->shmkey[0]);
        envp[1] = env_shmkey0;
    }
    if (it->shmkey[1] > 0) {
        sprintf(env_shmkey1, "DT_ENV_SHMKEY1=%016" PRIx64, it->shmkey[1]);
        envp[2] = env_shmkey1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        pr_err("fork failed: %s", strerror(errno));
        goto cleanup_pipe;
    }

    if (pid == 0) { // Child process
        setsid();
        chdir("/");

        close(STDIN_FILENO);
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);

        dup2(stdout_pipe[1], STDOUT_FILENO);
        dup2(stderr_pipe[1], STDERR_FILENO);

        close(stdout_pipe[1]);
        close(stderr_pipe[1]);

        if (it->desc->type == 'C') {
            char args[4096] = { 0 };
            if (it->args) {
                snprintf(args, sizeof(args) - 1, "%s %s",it->desc->name, it->args->data);
            } else {
                snprintf(args, sizeof(args) - 1, "%s",it->desc->name);
            }
            execlp("/bin/bash", "bash", "-c", args, NULL);
        } else {
            execve(it->desc->path, argv, envp);
        }
        _exit(1);
    }

    // === Parent process ===
    it->pid = pid;
    it->state = TASK_RUNNING;

    // Close write ends
    close(stdout_pipe[1]);
    close(stderr_pipe[1]);

    // Create a single thread to read and print both stdout + stderr
    pthread_t tid;
    struct itask_reader_arg *arg = malloc(sizeof(*arg));
    if (!arg) {
        // Memory allocation failed, return (child continues running)
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
        return 0;
    }
    arg->fd_out = stdout_pipe[0];
    arg->fd_err = stderr_pipe[0];
    arg->cmdret = it->cmdret;

    if (pthread_create(&tid, NULL, itask_reader_thread, arg) != 0) {
        pr_err("failed to create reader thread");
        close(stdout_pipe[0]);
        close(stderr_pipe[0]);
        free(arg);
        // Still consider startup successful
        return 0;
    }

    // Detach thread, it will automatically clean up when it exits
    pthread_detach(tid);

    return 0;

cleanup_pipe:
    if (stdout_pipe[0] >= 0) { close(stdout_pipe[0]); close(stdout_pipe[1]); }
    if (stderr_pipe[0] >= 0) { close(stderr_pipe[0]); close(stderr_pipe[1]); }
    return -1;
}

static void itask_wait(uint64_t id, void **retval)
{
    struct itask *it = itask_lookup(id);
    int status;

    if (it) {
        if (it->pid > 0) {
            waitpid(it->pid, &status, 0);
            it->state = TASK_FINISHED;
        }
        if (it->cmdret) {
            it->cmdret->result = WEXITSTATUS(status);
            *retval = (void *)(it->cmdret);
        } else if (it->ret) {
            *retval = (void *)(it->ret);
        }
    }
}

static void itask_clean(uint64_t id)
{
    struct itask *it = itask_lookup(id);
    char path[64];

    if (it) {
        if (it->pid > 0) {
            waitpid(it->pid, NULL, 0);
            it->state = TASK_FINISHED;
        }

        if (it->path)
            free(it->path);
        if (it->desc) {
            if (it->desc->path)
                free(it->desc->path);
            if (it->desc->name)
                free(it->desc->name);
            free(it->desc);
        }

        if (it->args) {
            munmap((void *)it->args, it->args->len + sizeof(struct dt_task_args));
        }
        if (it->shmkey[0] > 0) {
            memset(path, 0, sizeof(path));
            snprintf(path, sizeof(path), "%s-%016" PRIx64, SHM_PREFIX, it->shmkey[0]);
            shm_unlink(path);
        }

        if (it->ret) {
            munmap((void *)it->ret, it->ret->len + sizeof(struct dt_task_ret));
        }
        if (it->shmkey[1] > 0) {
            memset(path, 0, sizeof(path));
            snprintf(path, sizeof(path), "%s-%016" PRIx64, SHM_PREFIX, it->shmkey[1]);
            shm_unlink(path);
        }

        itask_remove(id);

        free(it);
    }
}

// Generic function to create error response messages
static dt_message_t *process_build_error(uint32_t id, uint32_t cmd, int64_t error_code)
{
    dt_message_t *msg_reply = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    if (!msg_reply) {
        perror("malloc failed for message reply");
        return NULL;
    }

    msg_reply->header.id = id;
    msg_reply->header.cmd = cmd;
    msg_reply->header.buf_size = sizeof(error_code);

    msg_reply->buf = xmalloc(msg_reply->header.buf_size);
    if (!msg_reply->buf) {
        perror("malloc failed for message buffer");
        xfree(msg_reply);
        return NULL;
    }

    memcpy(msg_reply->buf, &error_code, sizeof(error_code));
    return msg_reply;
}

// Handle registration message
static dt_message_t *process_task_register_msg(dt_message_t *msg)
{
    int64_t reply_errno = 0;

    if (itask_register(msg->header.id, msg->buf, msg->header.buf_size)) {
        reply_errno = -1;
    }

    return process_build_error(msg->header.id, CMD_RSP_REGISTER, reply_errno);
}

// Handle append arguments message
static dt_message_t *process_task_append_args_msg(dt_message_t *msg)
{
    int64_t reply_errno = 0;

    if (itask_append_args(msg->header.id, msg->buf, msg->header.buf_size)) {
        reply_errno = -1;
    }

    return process_build_error(msg->header.id, CMD_RSP_APPEND_ARGS, reply_errno);
}

// Handle append return value message
static dt_message_t *process_task_append_ret_msg(dt_message_t *msg)
{
    int64_t reply_errno = 0;

    if (itask_append_ret(msg->header.id, msg->buf)) {
        reply_errno = -1;
    }

    return process_build_error(msg->header.id, CMD_RSP_APPEND_RET, reply_errno);
}

// Handle start message
static dt_message_t *process_task_start_msg(dt_message_t *msg)
{
    int64_t reply_errno = 0;

    if (itask_start(msg->header.id)) {
        reply_errno = -1;
    }

    return process_build_error(msg->header.id, CMD_RSP_START, reply_errno);
}

// Handle wait message
static dt_message_t *process_task_wait_msg(dt_message_t *msg)
{
    struct dt_task_ret *taskret= NULL;
    struct dt_cmd_ret *cmdret= NULL;
    void *reply_ret = NULL;
    size_t msg_buf_size = 0;
    struct itask *it = NULL;

    it = itask_lookup(msg->header.id);
    if (it && it->desc) {
        itask_wait(msg->header.id, (void **)&reply_ret);
        if (!reply_ret) {
            return NULL;
        }
        if (it->desc->type == 'C') {
            cmdret = (struct dt_cmd_ret *)reply_ret;
            msg_buf_size = sizeof(struct dt_cmd_ret) + cmdret->outlen + cmdret->errlen;
        } else {
            taskret = (struct dt_task_ret *)reply_ret;
            msg_buf_size = sizeof(struct dt_task_ret) + taskret->len;
        }
    }

    dt_message_t *msg_reply = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    if (!msg_reply) {
        perror("malloc failed for message reply");
        return NULL;
    }

    msg_reply->header.id = msg->header.id;
    msg_reply->header.cmd = CMD_RSP_WAIT;
    msg_reply->header.buf_size = msg_buf_size;

    if (msg_reply->header.buf_size > 0) {
        msg_reply->buf = xmalloc(msg_reply->header.buf_size);
        if (!msg_reply->buf) {
            perror("malloc failed for message buffer");
            xfree(msg_reply);
            return NULL;
        }

        memcpy(msg_reply->buf, reply_ret, msg_reply->header.buf_size);
    }

    itask_clean(msg->header.id);
    return msg_reply;
}

dt_message_t *process_task_msg(dt_message_t *msg)
{
    dt_message_t *msg_reply = NULL;

    switch (msg->header.cmd) {
    case CMD_REQ_REGISTER:
        msg_reply = process_task_register_msg(msg);
        break;
    case CMD_REQ_APPEND_ARGS:
        msg_reply = process_task_append_args_msg(msg);
        break;
    case CMD_REQ_APPEND_RET:
        msg_reply = process_task_append_ret_msg(msg);
        break;
    case CMD_REQ_START:
        msg_reply = process_task_start_msg(msg);
        break;
    case CMD_REQ_WAIT:
        msg_reply = process_task_wait_msg(msg);
        break;
    default:
        break;
    }

    return msg_reply;
}
