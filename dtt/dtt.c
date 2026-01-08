#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>
#include <limits.h>
#include <stddef.h>
#include <pthread.h>
#include <inttypes.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <arpa/inet.h>

#include "is.h"
#include "md5.h"
#include "util.h"
#include "list.h"
#include "dynarray.h"
#include "log.h"
#include "helper.h"
#include "include/dtt.h"
#include "transfer.h"
#include "discovery.h"

#define CLUSTER_CONF       "/etc/cluster/node.conf"
#define DTTS_CLUSTER_CONF  "/tmp/dtts/cluster.hosts"

struct dynarray node_list = DYNARRAY_INIT(node_list);
static int load_balance_method = 0;

// like inode for fs
struct dt_itask {
    int32_t id;
    uint64_t ssid;
    char type;
    void *retval;
    struct list_head list;
};

dt_entry_t dt_task_arry[DT_TASK_SIZE];
size_t dt_task_len = 0;

LIST_HEAD(dt_itask_list);
static pthread_mutex_t dt_itask_lock = PTHREAD_MUTEX_INITIALIZER;

void itask_add(struct dt_itask *itask)
{
    INIT_LIST_HEAD(&itask->list);
    pthread_mutex_lock(&dt_itask_lock);
    list_add_tail(&itask->list, &dt_itask_list);
    pthread_mutex_unlock(&dt_itask_lock);
}

void itask_delete(int32_t task_id)
{
    struct list_head *pos;
    struct dt_itask *entry = NULL;
    bool found = false;

    pthread_mutex_lock(&dt_itask_lock);
    list_for_each(pos, &dt_itask_list) {
        entry = list_entry(pos, struct dt_itask, list);
        if (entry && entry->id == task_id) {
            found = true;
            break;
        }
    }
    if (found) {
        list_del(&entry->list);
        free(entry);
    }
    pthread_mutex_unlock(&dt_itask_lock);
}

char itask_get_type(int32_t task_id)
{
    struct list_head *pos;
    struct dt_itask *entry = NULL;
    char type = 0;

    if (task_id <= 0)
        return type;

    pthread_mutex_lock(&dt_itask_lock);
    list_for_each(pos, &dt_itask_list) {
        entry = list_entry(pos, struct dt_itask, list);
        if (entry && entry->id == task_id) {
            type = entry->type;
            break;
        }
    }
    pthread_mutex_unlock(&dt_itask_lock);

    return type;
}

uint64_t itask_get_ssid(int32_t task_id)
{
    struct list_head *pos;
    struct dt_itask *entry = NULL;
    uint64_t ssid = 0;

    if (task_id <= 0)
        return ssid;

    pthread_mutex_lock(&dt_itask_lock);
    list_for_each(pos, &dt_itask_list) {
        entry = list_entry(pos, struct dt_itask, list);
        if (entry && entry->id == task_id) {
            ssid = entry->ssid;
            break;
        }
    }
    pthread_mutex_unlock(&dt_itask_lock);

    return ssid;
}

dt_buf_t *itask_get_retval(int32_t task_id)
{
    struct list_head *pos;
    struct dt_itask *entry = NULL;
    dt_buf_t *retval = NULL;

    if (task_id <= 0)
        return retval;

    pthread_mutex_lock(&dt_itask_lock);
    list_for_each(pos, &dt_itask_list) {
        entry = list_entry(pos, struct dt_itask, list);
        if (entry && entry->id == task_id) {
            retval = entry->retval;
            break;
        }
    }
    pthread_mutex_unlock(&dt_itask_lock);

    return retval;
}

int itask_set_retval(int32_t task_id, void *retval)
{
    struct list_head *pos;
    struct dt_itask *entry = NULL;

    if (task_id <= 0)
        return -1;

    pthread_mutex_lock(&dt_itask_lock);
    list_for_each(pos, &dt_itask_list) {
        entry = list_entry(pos, struct dt_itask, list);
        if (entry && entry->id == task_id) {
            entry->retval = retval;
            break;
        }
    }
    pthread_mutex_unlock(&dt_itask_lock);

    return 0;
}

int file_compare_with_remote(dt_ssid_t ssid, const char *local_file,
        const char *remote_file)
{
    int result;
    mode_t local_mode;
    char local_md5[40] = {0};
    dt_filestat_t remote_stat = { 0 };
    dt_filehash_t remote_hash = { 0 };

    if (access(local_file, F_OK) == -1) {
        return -1;
    }

    if (file_stat_mode(local_file, &local_mode) != 0) {
        return -1;
    }

    if (file_calculate_md5(local_file, local_md5) != 0) {
        return -1;
    }

    // Check if the remote file exists
    int stat_result = dt_file_stat(ssid, remote_file, &remote_stat);
    if (stat_result != 0) {
        // Remote file does not exist
        return 0;
    }

    // Get remote file MD5
    int hash_result = dt_file_hash(ssid, remote_file, &remote_hash);
    if (hash_result != 0) {
        return -1;
    }

    // Compare MD5 and file permissions
    int md5_matches = (strcmp(local_md5, remote_hash.md5sum) == 0);
    int mode_matches = (local_mode == (remote_stat.mode & 0777));

    result = (md5_matches && mode_matches) ? 1 : 0;

    return result;
}

// Use mmap to read file content
static char* file_mmap_content(const char *filename, size_t *file_size)
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
        close(fd);
        return NULL;
    }

    // Memory map the file
    char *file_content = mmap(NULL, *file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file_content == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return NULL;
    }

    close(fd); // Can close the file descriptor after successful mapping
    return file_content;
}

// Unmap memory
static void file_unmap_content(char *file_content, size_t file_size)
{
    if (file_content != NULL) {
        munmap(file_content, file_size);
    }
}

// Transfer file to remote
static int file_transfer_to_remote(dt_ssid_t ssid, const char *local_file,
        const char *remote_file, mode_t mode)
{
    size_t file_size = 0;
    int result;

    char *file_content = file_mmap_content(local_file, &file_size);
    if (!file_content) {
        return -1;
    }

    // Write file to remote
    result = dt_file_write(ssid, remote_file, 0, file_size, file_content);
    if (result <= 0) {
        file_unmap_content(file_content, file_size);
        return -1;
    }

    // Set file permissions
    result = dt_file_chmod(ssid, remote_file, mode);
    if (result != 0) {
        file_unmap_content(file_content, file_size);
        return -1;
    }

    file_unmap_content(file_content, file_size);
    return 0;
}

static int file_transfer(dt_ssid_t ssid, const char *local_file,
        const char *remote_file)
{
    int result = 0;
    mode_t local_mode;
    char local_md5[40] = {0};
    dt_filestat_t remote_stat = { 0 };
    dt_filehash_t remote_hash = { 0 };

    if (access(local_file, F_OK) == -1) {
        return -1;
    }

    // Get local file information
    if (file_stat_mode(local_file, &local_mode) != 0) {
        return -1;
    }
    if (file_calculate_md5(local_file, local_md5) != 0) {
        return -1;
    }

    // Get remote file information
    int stat_result = dt_file_stat(ssid, remote_file, &remote_stat);
    if (stat_result != 0) {
        return file_transfer_to_remote(ssid, local_file, remote_file, local_mode);
    }
    int hash_result = dt_file_hash(ssid, remote_file, &remote_hash);
    if (hash_result != 0) {
        return -1;
    }

    // Compare MD5 and file permissions
    int md5_matches = (strcmp(local_md5, remote_hash.md5sum) == 0);
    int mode_matches = (local_mode == (remote_stat.mode & 0777));

    if (md5_matches && mode_matches) {
        result = 0;
    } else if (md5_matches && !mode_matches) {
        result = dt_file_chmod(ssid, remote_file, local_mode);
    } else if (!md5_matches) {
        // Delete remote file
        if (dt_file_remove(ssid, remote_file) != 0) {
            result = -1;
        } else {
            // Re-transfer the file
            result = file_transfer_to_remote(ssid, local_file, remote_file, local_mode);
        }
    }

    return result;
}

static dt_node_t* node_build_from_ssid(uint64_t ssid)
{
    dt_node_t *node = NULL;

    if (ssid <= 0)
        return NULL;

    node = (dt_node_t *)xmalloc(sizeof(dt_node_t));
    node->ssid = ssid;
    if (uint32_to_ipv4((uint32_t)(ssid & 0xffffffff), node->ip)) {
        xfree(node);
        return NULL;
    }

    return node;
}

static dt_node_t* node_lookup(uint64_t ssid)
{
    dt_node_t *node;

    if (ssid <= 0)
        return NULL;

    dynarray_for_each(node, &node_list) {
        if (node->ssid == ssid) {
            return node;
        }
    }

    return NULL;
}

static int node_load_aware_pick()
{
    int half_start;
    int half_size;
    int random_index;
    dt_node_t *node1, *node2;
    size_t len = dynarray_size(&node_list);
    int *indices = malloc(len * sizeof(int));

    for (size_t i = 0; i < len; i++) {
        indices[i] = i;
    }

    for (size_t i = 0; len > 0 && i < len; i++) {
        for (size_t j = i + 1; j < len; j++) {
            node1 = dynarray_get(&node_list, indices[i]);
            node2 = dynarray_get(&node_list, indices[j]);
            if (node1->avail_load > node2->avail_load) {
                int temp = indices[i];
                indices[i] = indices[j];
                indices[j] = temp;
            }
        }
    }

    half_start = len / 2;
    half_size = len - half_start;

    if (half_size <= 0) {
        return -1;
    }

    random_index = half_start + (random_uint32() % half_size);

    return indices[random_index];
}

static dt_node_t* node_pick()
{
    static int node_idx = -1;
    int method = load_balance_method;
    int len = dynarray_size(&node_list);

    if (method == LB_ROUND_ROBIN) {
        if (node_idx < 0) { // Random for first
            node_idx = random_uint32() % len;
        }
        node_idx++;
        node_idx = node_idx % len;
    } else if (method == LB_LOAD_AWARE) {
        node_idx = node_load_aware_pick();
    } else { // LB_RANDOM or unknown
        node_idx = random_uint32() % len;
    }

    return dynarray_get(&node_list, node_idx);
}

char *splite_first_by_space(const char *str)
{
    if (str == NULL) return NULL;

    while (*str == ' ') str++;

    if (*str == '\0') return strdup("");

    char *space_pos = strchr(str, ' ');

    if (space_pos == NULL) {
        return strdup(str);
    }

    int length = space_pos - str;
    char *result = malloc(length + 1);
    if (result) {
        strncpy(result, str, length);
        result[length] = '\0';
    }
    return result;
}

static char *find_command_full_path(const char *cmd)
{
    if (!cmd || !*cmd) {
        return NULL;
    }

    // Trim leading and trailing whitespace
    size_t len = strlen(cmd);
    const char *start = cmd;
    const char *end = cmd + len - 1;

    // Skip leading whitespace
    while (*start && isspace((unsigned char)*start)) {
        start++;
    }

    // Skip trailing whitespace
    while (end > start && isspace((unsigned char)*end)) {
        end--;
    }

    size_t trimmed_len = (end >= start) ? (end - start + 1) : 0;
    if (trimmed_len == 0) {
        return NULL;  // Command contains only whitespace
    }

    // Allocate memory for trimmed command
    char *trimmed_cmd = malloc(trimmed_len + 1);
    if (!trimmed_cmd) {
        return NULL;
    }
    memcpy(trimmed_cmd, start, trimmed_len);
    trimmed_cmd[trimmed_len] = '\0';

    // Check if command contains a path separator
    if (strchr(trimmed_cmd, '/')) {
        // Directly check the provided path
        if (access(trimmed_cmd, X_OK) == 0) {
            char *result = realpath(trimmed_cmd, NULL);
            free(trimmed_cmd);
            return result;
        }
        free(trimmed_cmd);
        return NULL;
    }

    // Thread-safe PATH search
    char *path_env = getenv("PATH");
    if (!path_env) {
        free(trimmed_cmd);
        return NULL;
    }

    char *result_path = NULL;
    char *path_copy = strdup(path_env);
    if (!path_copy) {
        free(trimmed_cmd);
        return NULL;
    }

    // Use strtok_r instead of strtok for thread safety
    char *saveptr = NULL;
    char *dir = strtok_r(path_copy, ":", &saveptr);

    while (dir != NULL) {
        // Treat empty PATH components as current directory
        if (*dir == '\0') {
            dir = ".";
        }

        // Build full path with dynamically calculated length
        size_t path_len = strlen(dir) + trimmed_len + 2;
        char *full_path = malloc(path_len);

        if (full_path) {
            snprintf(full_path, path_len, "%s/%s", dir, trimmed_cmd);

            if (access(full_path, X_OK) == 0) {
                // Get canonicalized path
                char *real_full_path = realpath(full_path, NULL);
                if (real_full_path) {
                    result_path = real_full_path;
                } else {
                    result_path = strdup(full_path);
                }
                free(full_path);
                break;
            }
            free(full_path);
        }

        dir = strtok_r(NULL, ":", &saveptr);
    }

    free(trimmed_cmd);
    free(path_copy);
    return result_path;
}

static void load_all_node_ips()
{
    uint32_t ssid = 0;
    char *local = "127.0.0.1";
    char tmp[128];
    char ip[16];
    char hostname[64];
    FILE *file = NULL;
    dt_node_t *node;

    if (access(CLUSTER_CONF, F_OK) == 0) {
        file = fopen(CLUSTER_CONF, "r");
        memset(tmp, 0, sizeof(tmp));
        while (fgets(tmp, sizeof(tmp), file)) {
            if (tmp[0] == '\n' || tmp[0] == '#') {
                continue;
            }
            tmp[strcspn(tmp, " \t\n\r")] = '\0';
            if (!is_valid_ipv4(tmp)) {
                continue;
            }

            node = (dt_node_t *)calloc(1, sizeof(dt_node_t));
            memcpy(node->ip, tmp, sizeof(node->ip) - 1);
            dynarray_append(&node_list, node);
        }
        fclose(file);
    }  else if (access(DTTS_CLUSTER_CONF, F_OK) == 0) {
        file = fopen(DTTS_CLUSTER_CONF, "r");
        memset(tmp, 0, sizeof(tmp));
        while (fgets(tmp, sizeof(tmp), file)) {
            if (tmp[0] == '\n' || tmp[0] == '#') {
                continue;
            }
            tmp[strcspn(tmp, "\t\n\r")] = '\0';

            memset(ip, 0, sizeof(ip));
            memset(hostname, 0, sizeof(hostname));
            if (sscanf(tmp, "%15s %127s", ip, hostname) == 2) {
                if (!is_valid_ipv4(ip)) {
                    continue;
                }
                node = (dt_node_t *)calloc(1, sizeof(dt_node_t));
                strncpy(node->ip, ip, sizeof(node->ip));
                memcpy(node->hostname, hostname, sizeof(node->hostname) - 1);
                dynarray_append(&node_list, node);
            }
        }
        fclose(file);
    } else {
        client_discovery(&node_list);
    }

    if (dynarray_size(&node_list) <= 0) {
        node = (dt_node_t *)calloc(1, sizeof(dt_node_t));
        strcpy(node->ip, local);
        dynarray_append(&node_list, node);
    }

    dynarray_for_each(node, &node_list) {
        if (ipv4_to_uint32(node->ip, &ssid) == 0) {
            node->ssid = ssid;
        }
    }
}

static int __dt_init()
{
    dt_buf_t args = { 0 };
    dt_buf_t retval = { 0 };
    char *env_task = getenv("DT_ENV_TASK");
    char *env_shmkey0 = NULL;
    char *env_shmkey1 = NULL;
    void *shmaddr = NULL;
    char path[64];
    struct stat shm_stat;
    int fd;

    if (env_task) {
        env_shmkey0 = getenv("DT_ENV_SHMKEY0");
        env_shmkey1 = getenv("DT_ENV_SHMKEY1");

        struct dt_task_args *targs = NULL;
        struct dt_task_ret *tretval = NULL;
        if (env_shmkey0) {
            memset(path, 0, sizeof(path));
            snprintf(path, sizeof(path), "%s-%s", SHM_PREFIX, env_shmkey0);
            fd = shm_open(path, O_RDWR, 0666);
            if (fd == -1) {
                return 1;
            }
            if (fstat(fd, &shm_stat) == -1) {
                close(fd);
                return 1;
            }
            shmaddr = mmap(0, shm_stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            if (shmaddr == MAP_FAILED) {
                close(fd);
                return 1;
            }
            close(fd);

            targs = (struct dt_task_args *)shmaddr;
            args.len = targs->len;
            args.data = (char *)shmaddr + sizeof(struct dt_task_args);
        }

        if (env_shmkey1) {
            memset(path, 0, sizeof(path));
            snprintf(path, sizeof(path), "%s-%s", SHM_PREFIX, env_shmkey1);
            fd = shm_open(path, O_RDWR, 0666);
            if (fd == -1) {
                return 1;
            }
            if (fstat(fd, &shm_stat) == -1) {
                close(fd);
                return 1;
            }
            shmaddr = mmap(0, shm_stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
            if (shmaddr == MAP_FAILED) {
                close(fd);
                return 1;
            }
            close(fd);

            tretval = (struct dt_task_ret *)shmaddr;
            retval.len = tretval->len;
            retval.data = (char *)shmaddr + sizeof(struct dt_task_ret);
        }

        for (size_t i = 0; i < dt_task_len; i++) {
            if (strncmp(dt_task_arry[i].name, env_task, strlen(env_task)))
                continue;

            dt_task_arry[i].func(!targs ? NULL : &args, !tretval ? NULL : &retval);
            if (targs) {
                munmap(targs, targs->len + sizeof(struct dt_task_args));
            }
            if (tretval) {
                munmap(tretval, tretval->len + sizeof(struct dt_task_ret));
            }

            return 1;
        }
    } else {
        load_all_node_ips();
    }

    return 0;
}

int dt_init()
{
    if (__dt_init())
        exit(0);
    return 0;
}

void dt_set_loadbalance(int lb)
{
    if (lb == LB_RANDOM || lb == LB_ROUND_ROBIN || lb == LB_LOAD_AWARE) {
        load_balance_method = lb;
    }
}

int32_t task_register(dt_ssid_t ssid, char type, const char *path, const char *name)
{
    dt_node_t *node = NULL;
    char data[128] = { 0 };
    size_t len = sizeof(data) - 1;

    if (ssid > 0) {
        node = node_lookup(ssid);
    } else {
        node = node_pick();
    }
    if (!node) {
        return -1;
    }

    data[0] = type;
    data[1] = ':';
    if (type == 'C') {
        len = sizeof(data) - strlen(data) - 1;
        snprintf(data + 2, len, "%s", path);
    } else {
        if (file_compare_with_remote(node->ssid, path, path) == 1) {
            len = sizeof(data) - strlen(data) - 1;
            snprintf(data + 2, len, "%s", path);
        } else {
            len = sizeof(data) - strlen(data) - 1;
            snprintf(data + 2, len, "%s/%s", TMP_DIR, basename_from_path(path));
            if (file_transfer(node->ssid, path, data + 2) != 0) {
                return -1;
            }
        }
    }
    strncat(data, ":", sizeof(data) - strlen(data) - 1);
    strncat(data, name, sizeof(data) - strlen(data) - 1);

    size_t data_len = strlen(data) + 1;
    dt_message_t *message = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    if (!message) {
        perror("malloc failed");
        return -1;
    }

    struct dt_itask *itask = malloc(sizeof(struct dt_itask));
    itask->ssid = node->ssid;
    itask->type = type;
    itask->retval = NULL;
    itask->id = random_uint32();
    itask_add(itask);

    message->header.id = itask->id;

    message->header.cmd = CMD_REQ_REGISTER;
    message->header.buf_size = data_len;

    message->buf = xmalloc(message->header.buf_size);
    if (!message->buf) {
        perror("malloc failed");
        xfree(message);
        return -1;
    }
    memcpy(message->buf, data, message->header.buf_size);

    dt_message_t *reply = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    client_send(node, message, reply);
    pr_info("Message %s 0x%x reply[0x%x] errno:%ld", node->ip,
            reply->header.id, reply->header.cmd, *((uint64_t *)reply->buf));

    xfree(message->buf);
    xfree(message);
    if (reply){
        xfree(reply->buf);
        xfree(reply);
    }

    return itask->id;
}

void task_append_args(int32_t task_id, dt_buf_t *args)
{
    dt_node_t *node = NULL;
    uint64_t ssid = 0;
    size_t args_header_size = offsetof(dt_buf_t, data);;
    if (!args) {
        return;
    }
    if (args->len <=0 || !args->data) {
        return;
    }

    size_t msg_buf_size = args_header_size + args->len;
    dt_message_t *message = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    if (!message) {
        perror("malloc failed");
        return;
    }

    message->header.id = task_id;
    message->header.cmd = CMD_REQ_APPEND_ARGS;
    message->header.buf_size = msg_buf_size;
    message->buf = xmalloc(args_header_size);
    message->data = args->data;
    message->header.data_len = args->len;
    memcpy(message->buf, (void *)args, args_header_size);

    ssid = itask_get_ssid(task_id);
    node = node_lookup(ssid);

    dt_message_t *reply = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    client_send(node, message, reply);
    pr_info("Message %s 0x%x reply[0x%x] errno:%ld", node->ip,
            reply->header.id, reply->header.cmd, *((uint64_t *)reply->buf));

    xfree(message->buf);
    xfree(message);
    if (reply) {
        xfree(reply->buf);
        xfree(reply);
    }
}

void task_append_cmdret(int32_t task_id, dt_ret_t *retval)
{
    uint64_t ssid = 0;
    dt_node_t *node = NULL;
    size_t ret_header_size = offsetof(struct dt_cmd_ret, result);;
    if (!retval) {
        return;
    }
    if (retval->outlen <=0 || !retval->out) {
        return;
    }

    size_t msg_buf_size = ret_header_size;
    dt_message_t *message = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    if (!message) {
        perror("malloc failed");
        return;
    }

    message->header.id = task_id;
    message->header.cmd = CMD_REQ_APPEND_RET;
    message->header.buf_size = msg_buf_size;
    message->buf = xmalloc(ret_header_size);
    memcpy(message->buf, (void *)retval, ret_header_size);

    itask_set_retval(task_id, (void *)retval);
    ssid = itask_get_ssid(task_id);
    node = node_lookup(ssid);

    dt_message_t *reply = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    client_send(node, message, reply);
    pr_info("Message %s 0x%x reply[0x%x] errno:%ld", node->ip,
            reply->header.id, reply->header.cmd, *((uint64_t *)reply->buf));

    xfree(message->buf);
    xfree(message);
    if (reply) {
        xfree(reply->buf);
        xfree(reply);
    }

}

void task_append_ret(int32_t task_id, dt_buf_t *retval)
{
    uint64_t ssid = 0;
    dt_node_t *node = NULL;
    size_t ret_header_size = offsetof(dt_buf_t, data);;
    if (!retval) {
        return;
    }
    if (retval->len <=0 || !retval->data) {
        return;
    }

    size_t msg_buf_size = ret_header_size;
    dt_message_t *message = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    if (!message) {
        perror("malloc failed");
        return;
    }

    message->header.id = task_id;
    message->header.cmd = CMD_REQ_APPEND_RET;
    message->header.buf_size = msg_buf_size;
    message->buf = xmalloc(ret_header_size);
    memcpy(message->buf, (void *)retval, ret_header_size);

    itask_set_retval(task_id, (void *)retval);
    ssid = itask_get_ssid(task_id);
    node = node_lookup(ssid);

    dt_message_t *reply = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    client_send(node, message, reply);
    pr_info("Message %s 0x%x reply[0x%x] errno:%ld", node->ip,
            reply->header.id, reply->header.cmd, *((uint64_t *)reply->buf));

    xfree(message->buf);
    xfree(message);
    if (reply) {
        xfree(reply->buf);
        xfree(reply);
    }
}

void task_start(int32_t task_id)
{
    uint64_t ssid = 0;
    dt_node_t *node = NULL;
    dt_message_t *message = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    if (!message) {
        perror("malloc failed");
        return;
    }

    message->header.id = task_id;
    message->header.cmd = CMD_REQ_START;
    message->header.buf_size = 0;

    ssid = itask_get_ssid(task_id);
    node = node_lookup(ssid);

    dt_message_t *reply = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    client_send(node, message, reply);
    pr_info("Message %s 0x%x reply[0x%x] errno:%ld", node->ip,
            reply->header.id, reply->header.cmd, *((uint64_t *)reply->buf));

    xfree(message);
    if (reply) {
        xfree(reply->buf);
        xfree(reply);
    }
}

void task_wait(int32_t task_id)
{
    uint64_t ssid = 0;
    dt_node_t *node = NULL;
    dt_buf_t *retval = NULL;
    dt_ret_t *cmdret = NULL;
    size_t ret_header_size = offsetof(dt_buf_t, data);
    dt_message_t *message = (dt_message_t *)xmalloc(sizeof(dt_message_t));

    if (!message) {
        perror("malloc failed");
        return;
    }

    message->header.id = task_id;
    message->header.cmd = CMD_REQ_WAIT;

    ssid = itask_get_ssid(task_id);
    node = node_lookup(ssid);

    dt_message_t *reply = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    client_send(node, message, reply);
    pr_info("Message %s 0x%x reply[0x%x] len:%ld", node->ip,
            reply->header.id, reply->header.cmd, reply->header.buf_size);

    if (itask_get_type(task_id) == 'C') {
        cmdret = (dt_ret_t *)itask_get_retval(task_id);
        if (cmdret) {
            struct dt_cmd_ret *cmd_reply = (struct dt_cmd_ret *)reply->buf;
            cmdret->result = cmd_reply->result;
            cmdret->outlen = cmd_reply->outlen;
            cmdret->errlen = cmd_reply->errlen;
            if (cmdret->outlen > 0 && cmdret->out) {
                memcpy(cmdret->out, cmd_reply->data, cmdret->outlen);
            }
            if (cmdret->errlen > 0 && cmdret->err) {
                memcpy(cmdret->err, cmd_reply->data + cmdret->outlen, cmdret->errlen);
            }
        }
    } else {
        retval = (dt_buf_t *)itask_get_retval(task_id);
        if (retval) {
            if ( retval->len > 0 && reply->header.buf_size > ret_header_size) {
                memcpy(retval->data, reply->buf + ret_header_size,
                        min(reply->header.buf_size - ret_header_size, retval->len));
            }
        }
    }
    itask_delete(task_id);
    xfree(message);
    if (reply) {
        xfree(reply->buf);
        xfree(reply);
    }
}

int dt_ping(dt_ssid_t ssid)
{
    int ret;
    struct dt_req_ping *req = NULL;
    struct dt_rsp_ping *rsp = NULL;
    dt_node_t *node = NULL;

    if (ssid > 0) {
        node = node_lookup(ssid);
    } else {
        node = node_pick();
    }
    if (!node) {
        return -1;
    }

    size_t msg_buf_size = sizeof(struct dt_req_ping);
    dt_message_t *msg = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    if (!msg) {
        ret = (errno == 0) ? -1 : -errno;
        return ret;
    }

    msg->header.id = random_uint32();
    msg->header.cmd = CMD_REQ_PING;
    msg->header.buf_size = msg_buf_size;

    msg->buf = xmalloc(msg->header.buf_size);
    if (!msg->buf) {
        ret = (errno == 0) ? -1 : -errno;
        xfree(msg);
        return ret;
    }

    req = (struct dt_req_ping *)(msg->buf);
    memcpy(req->data, "ping", 4);

    dt_message_t *reply = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    client_send(node, msg, reply);
    pr_info("Message %s 0x%x reply[0x%x]", node->ip, reply->header.id, reply->header.cmd);
    if (reply->header.buf_size == sizeof(struct dt_rsp_ping)) {
        rsp = (struct dt_rsp_ping *)(reply->buf);
        if (strncmp(rsp->data, "pong", 4) == 0) {
            ret = 0;
        } else {
            ret = -1;
        }
    } else {
        ret = -22;
    }

    xfree(msg->buf);
    xfree(msg);
    if (reply) {
        xfree(reply->buf);
        xfree(reply);
    }

    return ret;
}

int dt_loglevel_get(dt_ssid_t ssid)
{
    int ret;
    struct dt_req_loglevel *req = NULL;
    struct dt_rsp_loglevel *rsp = NULL;
    dt_node_t *node = NULL;

    if (ssid > 0) {
        node = node_lookup(ssid);
    } else {
        node = node_pick();
    }
    if (!node) {
        return -1;
    }

    size_t msg_buf_size = sizeof(struct dt_req_loglevel);
    dt_message_t *msg = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    if (!msg) {
        ret = (errno == 0) ? -1 : -errno;
        return ret;
    }

    msg->header.id = random_uint32();
    msg->header.cmd = CMD_REQ_LOGLEVEL;
    msg->header.buf_size = msg_buf_size;

    msg->buf = xmalloc(msg->header.buf_size);
    if (!msg->buf) {
        ret = (errno == 0) ? -1 : -errno;
        xfree(msg);
        return ret;
    }

    req = (struct dt_req_loglevel *)(msg->buf);
    req->operation = 0;

    dt_message_t *reply = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    client_send(node, msg, reply);
    pr_info("Message %s 0x%x reply[0x%x]", node->ip, reply->header.id, reply->header.cmd);
    if (reply->header.buf_size == sizeof(struct dt_rsp_loglevel)) {
        rsp = (struct dt_rsp_loglevel *)(reply->buf);
        if (rsp->retval == 0) {
            ret = rsp->cur_loglevel;
        } else {
            ret = -2;
        }
    } else {
        ret = -22;
    }

    xfree(msg->buf);
    xfree(msg);
    if (reply) {
        xfree(reply->buf);
        xfree(reply);
    }

    return ret;
}

int dt_loglevel_set(dt_ssid_t ssid, int level)
{
    int ret;
    struct dt_req_loglevel *req = NULL;
    struct dt_rsp_loglevel *rsp = NULL;
    dt_node_t *node = NULL;

    if (ssid > 0) {
        node = node_lookup(ssid);
    } else {
        node = node_pick();
    }
    if (!node) {
        return -1;
    }

    size_t msg_buf_size = sizeof(struct dt_req_loglevel);
    dt_message_t *msg = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    if (!msg) {
        ret = (errno == 0) ? -1 : -errno;
        return ret;
    }

    msg->header.id = random_uint32();
    msg->header.cmd = CMD_REQ_LOGLEVEL;
    msg->header.buf_size = msg_buf_size;

    msg->buf = xmalloc(msg->header.buf_size);
    if (!msg->buf) {
        ret = (errno == 0) ? -1 : -errno;
        xfree(msg);
        return ret;
    }

    req = (struct dt_req_loglevel *)(msg->buf);
    req->operation = 1;
    req->loglevel = level;

    dt_message_t *reply = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    client_send(node, msg, reply);
    pr_info("Message %s 0x%x reply[0x%x]", node->ip, reply->header.id, reply->header.cmd);
    if (reply->header.buf_size == sizeof(struct dt_rsp_loglevel)) {
        rsp = (struct dt_rsp_loglevel *)(reply->buf);
        if (rsp->retval == 0) {
            ret = 0;
        } else {
            ret = -2;
        }
    } else {
        ret = -22;
    }

    xfree(msg->buf);
    xfree(msg);
    if (reply) {
        xfree(reply->buf);
        xfree(reply);
    }

    return ret;
}

int32_t dt_cmd_create(dt_ssid_t ssid, const char *cmd, dt_ret_t *ret)
{
    (void) ret;
    int32_t id;
    char *path = NULL;

    char *command = splite_first_by_space(cmd);
    if (command[0] == '/' ) {
        id = task_register(ssid, 'C', command, cmd);
    } else {
        path = find_command_full_path(command);
        if (!path) {
            path = strdup(command);
        }
        id = task_register(ssid, 'C', path, cmd);
        if (path) free(path);
    }
    xfree(command);

    if (id <= 0) {
        return -1;
    }

    task_append_cmdret(id, ret);
    task_start(id);
    return id;
}

int32_t _dt_task_create(dt_ssid_t ssid, const char *name, dt_buf_t *args, dt_buf_t *ret)
{
    int32_t task_id;
    char path[PATH_MAX] = {};
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len <= 0) {
        perror("readlink");
        return -1;
    }

    task_id = task_register(ssid, 'T', path, name);
    if (task_id <= 0) {
        return -1;
    }

    /**
    int input = 123456789;
    int output = 0;

    dt_buf_t *args = (dt_buf_t *)calloc(1, sizeof(dt_buf_t) + sizeof(input));
    args->len = sizeof(input);
    *((int *)args->data) = input;

    dt_buf_t *ret= (dt_buf_t *)calloc(1, sizeof(dt_buf_t) + sizeof(output));
    ret->len = sizeof(output);
    */

    task_append_args(task_id, args);
    task_append_ret(task_id, ret);
    task_start(task_id);

    return task_id;
}

int dt_join(int32_t task_id)
{
    task_wait(task_id);
    return 0;
}

int dt_file_write(dt_ssid_t ssid, const char *path, uint64_t offset, uint64_t len, char *data)
{
    struct dt_req_filewrite *req = NULL;
    size_t req_header_size = offsetof(struct dt_req_filewrite, data);
    struct dt_rsp_filewrite *rsp = NULL;
    int64_t reply_val = 0;
    dt_node_t *node = NULL;

    if (ssid > 0) {
        node = node_lookup(ssid);
    } else {
        node = node_pick();
    }
    if (!node) {
        return -1;
    }

    size_t msg_buf_size = req_header_size + len;
    dt_message_t *message = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    if (!message) {
        pr_err("malloc failed");
        return -1;
    }

    message->header.id = random_uint32();
    message->header.cmd = CMD_REQ_FILEWRITE;
    message->header.buf_size = msg_buf_size;
    message->buf = xmalloc(req_header_size);
    message->data = data;
    message->header.data_len = len;
    req = (struct dt_req_filewrite *)message->buf;

    strncpy(req->path, path, sizeof(req->path) - 1);
    req->offset = offset;
    req->len = len;

    dt_message_t *reply = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    client_send(node, message, reply);
    pr_info("Message %s 0x%x reply[0x%x]", node->ip, reply->header.id, reply->header.cmd);
    if (reply->header.buf_size != sizeof(int64_t)) {
        reply_val = -1;
    } else {
        rsp = (struct dt_rsp_filewrite *)(reply->buf);
        reply_val = rsp->len;
    }

    xfree(message->buf);
    xfree(message);
    if (reply) {
        xfree(reply->buf);
        xfree(reply);
    }

    return reply_val;
}

int dt_file_read(dt_ssid_t ssid, const char *path, uint64_t offset, uint64_t len, char *data)
{
    struct dt_req_fileread *req = NULL;
    struct dt_rsp_fileread *rsp = NULL;
    int64_t reply_val = 0;
    dt_node_t *node = NULL;

    if (ssid > 0) {
        node = node_lookup(ssid);
    } else {
        node = node_pick();
    }
    if (!node) {
        return -1;
    }

    size_t msg_buf_size = sizeof(struct dt_req_fileread);
    dt_message_t *message = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    if (!message) {
        pr_err("malloc failed");
        return -1;
    }

    message->header.id = random_uint32();
    message->header.cmd = CMD_REQ_FILEREAD;
    message->header.buf_size = msg_buf_size;
    message->buf = xmalloc(msg_buf_size);

    req = (struct dt_req_fileread *)message->buf;
    strncpy(req->path, path, sizeof(req->path) - 1);
    req->offset = offset;
    req->len = len;

    dt_message_t *reply = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    reply->data = data;
    client_send(node, message, reply);
    pr_info("Message %s 0x%x reply[0x%x]", node->ip, reply->header.id, reply->header.cmd);
    if (reply->header.buf_size < offsetof(struct dt_rsp_fileread, data)) {
        reply_val = -1;
    } else {
        rsp = (struct dt_rsp_fileread *)(reply->buf);
        reply_val = rsp->len;
    }

    xfree(message->buf);
    xfree(message);
    if (reply) {
        xfree(reply->buf);
        xfree(reply);
    }

    return reply_val;
}

int dt_file_stat(dt_ssid_t ssid, const char *path, dt_filestat_t *st)
{
    int ret = -1;
    struct dt_req_filestat *req = NULL;
    struct dt_rsp_filestat *rsp = NULL;
    dt_node_t *node = NULL;

    if (ssid > 0) {
        node = node_lookup(ssid);
    } else {
        node = node_pick();
    }
    if (!node) {
        return -1;
    }

    size_t msg_buf_size = sizeof(struct dt_req_filestat);
    dt_message_t *msg = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    if (!msg) {
        pr_err("malloc failed");
        return -1;
    }

    msg->header.id = random_uint32();
    msg->header.cmd = CMD_REQ_FILESTAT;
    msg->header.buf_size = msg_buf_size;

    msg->buf = xmalloc(msg->header.buf_size);
    if (!msg->buf) {
        perror("malloc failed");
        xfree(msg);
        return -1;
    }

    req = (struct dt_req_filestat *)(msg->buf);
    strncpy(req->path, path, sizeof(req->path) - 1);

    dt_message_t *reply = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    client_send(node, msg, reply);
    pr_info("Message %s 0x%x reply[0x%x]", node->ip, reply->header.id, reply->header.cmd);
    if (reply->header.buf_size != sizeof(struct dt_rsp_filestat)) {
        ret = -1;
    } else {
        rsp = (struct dt_rsp_filestat *)(reply->buf);
        ret = rsp->retval;
        st->mode = rsp->mode;
        st->type = rsp->type;
        st->size = rsp->size;
    }

    xfree(msg->buf);
    xfree(msg);
    if (reply) {
        xfree(reply->buf);
        xfree(reply);
    }

    return ret;
}

int dt_file_hash(dt_ssid_t ssid, const char *path, dt_filehash_t *fh)
{
    int ret = -1;
    struct dt_req_filehash *req = NULL;
    struct dt_rsp_filehash *rsp = NULL;
    dt_node_t *node = NULL;

    if (ssid > 0) {
        node = node_lookup(ssid);
    } else {
        node = node_pick();
    }
    if (!node) {
        return -1;
    }

    size_t msg_buf_size = sizeof(struct dt_req_filehash);
    dt_message_t *msg = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    if (!msg) {
        pr_err("malloc failed");
        return -1;
    }

    msg->header.id = random_uint32();
    msg->header.cmd = CMD_REQ_FILEHASH;
    msg->header.buf_size = msg_buf_size;

    msg->buf = xmalloc(msg->header.buf_size);
    if (!msg->buf) {
        perror("malloc failed");
        xfree(msg);
        return -1;
    }

    req = (struct dt_req_filehash *)(msg->buf);
    strncpy(req->path, path, sizeof(req->path) - 1);

    dt_message_t *reply = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    client_send(node, msg, reply);
    pr_info("Message %s 0x%x reply[0x%x]", node->ip, reply->header.id, reply->header.cmd);
    if (reply->header.buf_size != sizeof(struct dt_rsp_filehash)) {
        ret = -1;
    } else {
        rsp = (struct dt_rsp_filehash *)(reply->buf);
        ret = rsp->retval;
        memcpy(fh->md5sum, rsp->md5sum, min(sizeof(fh->md5sum), sizeof(rsp->md5sum)));
    }

    xfree(msg->buf);
    xfree(msg);
    if (reply) {
        xfree(reply->buf);
        xfree(reply);
    }

    return ret;
}

int dt_file_remove(dt_ssid_t ssid, const char *path)
{
    int ret = -1;
    struct dt_req_fileremove *req = NULL;
    struct dt_rsp_fileremove *rsp = NULL;
    dt_node_t *node = NULL;

    if (ssid > 0) {
        node = node_lookup(ssid);
    } else {
        node = node_pick();
    }
    if (!node) {
        return -1;
    }

    size_t msg_buf_size = sizeof(struct dt_req_fileremove);
    dt_message_t *msg = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    if (!msg) {
        pr_err("malloc failed");
        return -1;
    }

    msg->header.id = random_uint32();
    msg->header.cmd = CMD_REQ_FILEREMOVE;
    msg->header.buf_size = msg_buf_size;

    msg->buf = xmalloc(msg->header.buf_size);
    if (!msg->buf) {
        perror("malloc failed");
        xfree(msg);
        return -1;
    }

    req = (struct dt_req_fileremove *)(msg->buf);
    strncpy(req->path, path, sizeof(req->path) - 1);

    dt_message_t *reply = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    client_send(node, msg, reply);
    pr_info("Message %s 0x%x reply[0x%x]", node->ip, reply->header.id, reply->header.cmd);
    if (reply->header.buf_size != sizeof(struct dt_rsp_fileremove)) {
        ret = -1;
    } else {
        rsp = (struct dt_rsp_fileremove *)(reply->buf);
        ret = rsp->retval;
    }

    xfree(msg->buf);
    xfree(msg);
    if (reply) {
        xfree(reply->buf);
        xfree(reply);
    }

    return ret;
}

int dt_file_chmod(dt_ssid_t ssid, const char *path, uint16_t mode)
{
    int ret = -1;
    struct dt_req_filechmod *req = NULL;
    struct dt_rsp_filechmod *rsp = NULL;
    dt_node_t *node = NULL;

    if (ssid > 0) {
        node = node_lookup(ssid);
    } else {
        node = node_pick();
    }
    if (!node) {
        return -1;
    }

    size_t msg_buf_size = sizeof(struct dt_req_filechmod);
    dt_message_t *msg = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    if (!msg) {
        pr_err("malloc failed");
        return -1;
    }

    msg->header.id = random_uint32();
    msg->header.cmd = CMD_REQ_FILECHMOD;
    msg->header.buf_size = msg_buf_size;

    msg->buf = xmalloc(msg->header.buf_size);
    if (!msg->buf) {
        perror("malloc failed");
        xfree(msg);
        return -1;
    }

    req = (struct dt_req_filechmod *)(msg->buf);
    strncpy(req->path, path, sizeof(req->path) - 1);
    req->mode = mode;

    dt_message_t *reply = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    client_send(node, msg, reply);
    pr_info("Message %s 0x%x reply[0x%x]", node->ip, reply->header.id, reply->header.cmd);
    if (reply->header.buf_size != sizeof(struct dt_rsp_filechmod)) {
        ret = -1;
    } else {
        rsp = (struct dt_rsp_filechmod *)(reply->buf);
        ret = rsp->retval;
    }

    xfree(msg->buf);
    xfree(msg);
    if (reply) {
        xfree(reply->buf);
        xfree(reply);
    }

    return ret;
}

dt_addr_t *dt_addr_offset(dt_addr_t *addr, size_t offset)
{
    addr->offset = offset;
    return addr;
}

dt_addr_t *dt_addr_add(dt_addr_t *addr, size_t len)
{
    addr->offset += len;
    return addr;
}

dt_addr_t *dt_addr_sub(dt_addr_t *addr, size_t len)
{
    addr->offset -= len;
    return addr;
}

dt_addr_t *dt_malloc(dt_ssid_t ssid, size_t size)
{
    dt_addr_t *ret = NULL;
    struct dt_req_malloc *req = NULL;
    struct dt_rsp_malloc *rsp = NULL;
    dt_node_t *node = NULL;

    if (ssid > 0) {
        node = node_lookup(ssid);
    } else {
        node = node_pick();
    }
    if (!node) {
        return ret;
    }

    size_t msg_buf_size = sizeof(struct dt_req_malloc);
    dt_message_t *msg = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    if (!msg) {
        pr_err("malloc failed");
        return ret;
    }

    msg->header.id = random_uint32();
    msg->header.cmd = CMD_REQ_MALLOC;
    msg->header.buf_size = msg_buf_size;

    msg->buf = xmalloc(msg->header.buf_size);
    if (!msg->buf) {
        perror("malloc failed");
        xfree(msg);
        return ret;
    }

    req = (struct dt_req_malloc *)(msg->buf);
    req->size = (uint64_t)size;
    req->ssid = node->ssid;

    dt_message_t *reply = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    client_send(node, msg, reply);
    pr_info("Message %s 0x%x reply[0x%x]", node->ip, reply->header.id, reply->header.cmd);
    if (reply->header.buf_size == sizeof(struct dt_rsp_malloc)) {
        rsp = (struct dt_rsp_malloc *)(reply->buf);
        ret = (dt_addr_t *)xmalloc(sizeof(dt_addr_t));
        ret->low = rsp->low;
        ret->high = rsp->high;
        ret->size = size;
        ret->offset = 0;
        ret->mmap_ptr = 0;
    }

    xfree(msg->buf);
    xfree(msg);
    if (reply) {
        xfree(reply->buf);
        xfree(reply);
    }

    return ret;
}

int dt_free(dt_addr_t *addr)
{
    int ret;
    struct dt_req_free *req = NULL;
    struct dt_rsp_free *rsp = NULL;
    dt_node_t *node = NULL;

    node = node_lookup(addr->high);
    if (!node) {
        return -1;
    }

    size_t msg_buf_size = sizeof(struct dt_req_free);
    dt_message_t *msg = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    if (!msg) {
        pr_err("malloc failed");
        return -1;
    }

    msg->header.id = random_uint32();
    msg->header.cmd = CMD_REQ_FREE;
    msg->header.buf_size = msg_buf_size;

    msg->buf = xmalloc(msg->header.buf_size);
    if (!msg->buf) {
        perror("malloc failed");
        xfree(msg);
        return -1;
    }

    req = (struct dt_req_free *)(msg->buf);
    req->low = addr->low;
    req->high = addr->high;

    dt_message_t *reply = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    client_send(node, msg, reply);
    pr_info("Message %s 0x%x reply[0x%x]", node->ip, reply->header.id, reply->header.cmd);
    if (reply->header.buf_size == sizeof(struct dt_rsp_free)) {
        rsp = (struct dt_rsp_free *)(reply->buf);
        ret = rsp->retval;
    } else {
        ret = -1;
    }

    xfree(msg->buf);
    xfree(msg);
    if (reply) {
        xfree(reply->buf);
        xfree(reply);
    }

    return ret;
}

// Only used inside tasks
void *dt_mmap(dt_addr_t *addr)
{
    int fd;
    char path[128] = { 0 };

    snprintf(path, sizeof(path), "%s-%016" PRIx64, SHM_PREFIX, addr->low);

    fd = shm_open(path, O_RDWR, 0666);
    if (fd == -1) {
        return NULL;
    }

    void *ptr = mmap(0, addr->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        return NULL;
    }
    close(fd);

    addr->mmap_ptr = (uint64_t)ptr;
    return ptr + addr->offset;
}

// Only used inside tasks
void dt_munmap(dt_addr_t *addr)
{
    if (!addr->mmap_ptr)
        return;
    munmap((void *)addr->mmap_ptr, addr->size);
}

int dt_memset(dt_addr_t *addr, char val, size_t len)
{
    int ret;
    struct dt_req_memset *req = NULL;
    struct dt_rsp_memset *rsp = NULL;
    dt_node_t *node = NULL;

    node = node_lookup(addr->high);
    if (!node) {
        return -1;
    }

    size_t msg_buf_size = sizeof(struct dt_req_memset);
    dt_message_t *msg = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    if (!msg) {
        pr_err("malloc failed");
        return -1;
    }

    msg->header.id = random_uint32();
    msg->header.cmd = CMD_REQ_MEMSET;
    msg->header.buf_size = msg_buf_size;

    msg->buf = xmalloc(msg->header.buf_size);
    if (!msg->buf) {
        perror("malloc failed");
        xfree(msg);
        return -1;
    }

    req = (struct dt_req_memset *)(msg->buf);
    req->low = addr->low;
    req->high = addr->high;
    req->offset = addr->offset;
    req->size = addr->size;
    req->len = len;
    req->val = val;

    dt_message_t *reply = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    client_send(node, msg, reply);
    pr_info("Message %s 0x%x reply[0x%x]", node->ip, reply->header.id, reply->header.cmd);
    if (reply->header.buf_size == sizeof(struct dt_rsp_memset)) {
        rsp = (struct dt_rsp_memset *)(reply->buf);
        ret = rsp->retval;
    } else {
        ret = -1;
    }

    xfree(msg->buf);
    xfree(msg);
    if (reply) {
        xfree(reply->buf);
        xfree(reply);
    }

    return ret;
}

void *dt_memcpy_from(void *to, dt_addr_t *from, size_t len)
{
    void *ret;
    struct dt_req_memcpyfrom *req = NULL;
    struct dt_rsp_memcpyfrom *rsp = NULL;
    dt_node_t *node = NULL;
    dt_node_t *build_node = NULL;

    node = node_lookup(from->high);
    if (!node) {
        // If called on the server side, construct a node struct.
        build_node = node_build_from_ssid(from->high);
        if (build_node) {
            node = build_node;
        } else {
            return NULL;
        }
    }

    size_t msg_buf_size = sizeof(struct dt_req_memcpyfrom);
    dt_message_t *msg = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    if (!msg) {
        return NULL;
    }

    msg->header.id = random_uint32();
    msg->header.cmd = CMD_REQ_MEMCPYFROM;
    msg->header.buf_size = msg_buf_size;

    msg->buf = xmalloc(msg->header.buf_size);
    if (!msg->buf) {
        xfree(msg);
        return NULL;
    }

    req = (struct dt_req_memcpyfrom *)(msg->buf);
    req->low = from->low;
    req->high = from->high;
    req->offset = from->offset;
    req->size = from->size;
    req->len = len;

    dt_message_t *reply = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    reply->data = to;
    client_send(node, msg, reply);
    pr_info("Message %s 0x%x reply[0x%x]", node->ip, reply->header.id, reply->header.cmd);
    if (reply->header.buf_size < offsetof(struct dt_rsp_memcpyfrom, data)) {
        ret = NULL;
    } else {
        rsp = (struct dt_rsp_memcpyfrom *)(reply->buf);
        if (rsp->retval == 0) {
            ret = to;
        } else {
            ret = NULL;
        }
    }

    xfree(msg->buf);
    xfree(msg);
    if (reply) {
        xfree(reply->buf);
        xfree(reply);
    }
    xfree(build_node);

    return ret;
}

dt_addr_t *dt_memcpy_to(dt_addr_t *to, void *from, size_t len)
{
    dt_addr_t *ret;
    struct dt_req_memcpyto *req = NULL;
    size_t req_header_size = offsetof(struct dt_req_memcpyto, data);
    struct dt_rsp_memcpyto *rsp = NULL;
    dt_node_t *node = NULL;
    dt_node_t *build_node = NULL;

    node = node_lookup(to->high);
    if (!node) {
        // If called on the server side, construct a node struct.
        build_node = node_build_from_ssid(to->high);
        if (build_node) {
            node = build_node;
        } else {
            return NULL;
        }
    }

    size_t msg_buf_size = req_header_size + len;
    dt_message_t *msg = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    if (!msg) {
        xfree(build_node);
        return NULL;
    }

    msg->header.id = random_uint32();
    msg->header.cmd = CMD_REQ_MEMCPYTO;
    msg->header.buf_size = msg_buf_size;
    msg->header.data_len = len;
    msg->data = (char *)from;

    msg->buf = xmalloc(sizeof(struct dt_req_memcpyto));
    if (!msg->buf) {
        xfree(build_node);
        xfree(msg);
        return NULL;
    }

    req = (struct dt_req_memcpyto *)(msg->buf);
    req->low = to->low;
    req->high = to->high;
    req->offset = to->offset;
    req->size = to->size;
    req->len = len;
    req->data = (char *)from;

    dt_message_t *reply = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    client_send(node, msg, reply);
    pr_info("Message %s 0x%x reply[0x%x]", node->ip, reply->header.id, reply->header.cmd);
    if (reply->header.buf_size < sizeof(struct dt_rsp_memcpyto)) {
        ret = NULL;
    } else {
        rsp = (struct dt_rsp_memcpyto *)(reply->buf);
        if (rsp->retval == 0) {
            ret = to;
        } else {
            ret = NULL;
        }
    }

    xfree(msg->buf);
    xfree(msg);
    if (reply) {
        xfree(reply->buf);
        xfree(reply);
    }
    xfree(build_node);

    return ret;
}

dt_addr_t *dt_memcpy(dt_addr_t *to, dt_addr_t *from, size_t len)
{
    dt_addr_t *ret;
    struct dt_req_memcpy *req = NULL;
    struct dt_rsp_memcpy *rsp = NULL;
    dt_node_t *node = NULL;
    dt_node_t *build_node = NULL;

    node = node_lookup(from->high);
    if (!node) {
        // If called on the server side, construct a node struct.
        build_node = node_build_from_ssid(from->high);
        if (build_node) {
            node = build_node;
        } else {
            return NULL;
        }
    }

    size_t msg_buf_size = sizeof(struct dt_req_memcpy);
    dt_message_t *msg = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    if (!msg) {
        return NULL;
    }

    msg->header.id = random_uint32();
    msg->header.cmd = CMD_REQ_MEMCPY;
    msg->header.buf_size = msg_buf_size;

    msg->buf = xmalloc(msg->header.buf_size);
    if (!msg->buf) {
        xfree(msg);
        return NULL;
    }

    req = (struct dt_req_memcpy *)(msg->buf);
    req->from_low = from->low;
    req->from_high = from->high;
    req->from_offset = from->offset;
    req->from_size = from->size;
    req->to_low = to->low;
    req->to_high = to->high;
    req->to_offset = to->offset;
    req->to_size = to->size;
    req->len = len;

    dt_message_t *reply = (dt_message_t *)xmalloc(sizeof(dt_message_t));
    client_send(node, msg, reply);
    pr_info("Message %s 0x%x reply[0x%x]", node->ip, reply->header.id, reply->header.cmd);
    if (reply->header.buf_size < sizeof(struct dt_rsp_memcpy)) {
        ret = NULL;
    } else {
        rsp = (struct dt_rsp_memcpy *)(reply->buf);
        if (rsp->retval == 0) {
            ret = to;
        } else {
            ret = NULL;
        }
    }

    xfree(msg->buf);
    xfree(msg);
    if (reply) {
        xfree(reply->buf);
        xfree(reply);
    }
    xfree(build_node);

    return ret;
}
