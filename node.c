#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#include "util.h"
#include "log.h"
#include "dtt/transfer.h"

static int get_cpu_cores()
{
    FILE *fp;
    char buffer[256];
    int cores = 0;

    // Read /proc/cpuinfo
    fp = fopen("/proc/cpuinfo", "r");
    if (fp != NULL) {
        while (fgets(buffer, sizeof(buffer), fp)) {
            if (strstr(buffer, "processor") && strstr(buffer, ":")) {
                cores++;
            }
        }
        fclose(fp);
    }

    // Call sysconf
    if (cores == 0) {
        cores = sysconf(_SC_NPROCESSORS_ONLN);
    }

    return cores > 0 ? cores : 1;
}

static float get_cpu_5min_load()
{
    FILE *fp;
    float load_1min, load_5min, load_15min;

    fp = fopen("/proc/loadavg", "r");
    if (fp == NULL) {
        return -1.0f;
    }

    if (fscanf(fp, "%f %f %f", &load_1min, &load_5min, &load_15min) != 3) {
        fclose(fp);
        return -1.0f;
    }

    fclose(fp);
    return load_5min;
}

static long long get_mem_available()
{
    FILE *fp;
    char line[256];
    long long mem_available = -1;

    fp = fopen("/proc/meminfo", "r");
    if (fp == NULL) {
        perror("Failed to open /proc/meminfo");
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        // Search MemAvailable
        if (strstr(line, "MemAvailable:") != NULL) {
            sscanf(line, "MemAvailable: %lld kB", &mem_available);
            break;
        }
    }

    fclose(fp);
    return mem_available;
}

static int64_t available_cpu_load_capacity(float load_5min, int cpu_cores)
{
    float available = (cpu_cores - load_5min) * 100.0;

    if (available < 1.0) {
        available = 1.0;
    }

    return (int64_t)available;
}

static int64_t available_mem_load_capacity(long long mem_available)
{
    float available = (float)mem_available / 1024.0 / 1024.0 * 10.0;

    if (available < 1.0) {
        available = 1.0;
    }

    return (int64_t)available;
}

int64_t available_load_capacity()
{
    uint64_t avail_cpu;
    uint64_t avail_mem;

    int cpu_cores = get_cpu_cores();
    float load_5min = get_cpu_5min_load();
    avail_cpu = available_cpu_load_capacity(load_5min, cpu_cores);

    long long mem_available = get_mem_available();
    avail_mem = available_mem_load_capacity(mem_available);

    return avail_cpu + avail_mem;
}

static dt_message_t *process_ping_msg(dt_message_t *msg)
{
    struct dt_req_ping *req = (struct dt_req_ping *)msg->buf;
    struct dt_rsp_ping *rsp = NULL;

    dt_message_t *msg_reply = xmalloc(sizeof(dt_message_t));
    if (!msg_reply) {
        pr_err("calloc failed");
        return NULL;
    }

    msg_reply->header.cmd = CMD_RSP_PING;
    msg_reply->header.id = msg->header.id;
    msg_reply->header.buf_size = sizeof(struct dt_rsp_ping);
    msg_reply->buf = xmalloc(msg_reply->header.buf_size);
    if (!msg_reply->buf) {
        perror("calloc failed");
        xfree(msg_reply);
        return NULL;
    }
    rsp = (struct dt_rsp_ping *)(msg_reply->buf);
    if (msg->header.buf_size == sizeof(struct dt_req_ping)) {
        if (strncmp(req->data, "ping", 4) == 0) {
            pr_debug("Reply pong message");
            memcpy(rsp->data, "pong", 4);
        }
    }

    return msg_reply;
}

static dt_message_t *process_loglevel_msg(dt_message_t *msg)
{
    struct dt_req_loglevel *req = (struct dt_req_loglevel *)msg->buf;
    struct dt_rsp_loglevel *rsp = NULL;

    dt_message_t *msg_reply = xmalloc(sizeof(dt_message_t));
    if (!msg_reply) {
        pr_err("calloc failed");
        return NULL;
    }

    msg_reply->header.cmd = CMD_RSP_LOGLEVEL;
    msg_reply->header.id = msg->header.id;
    msg_reply->header.buf_size = sizeof(struct dt_rsp_loglevel);
    msg_reply->buf = xmalloc(msg_reply->header.buf_size);
    if (!msg_reply->buf) {
        perror("calloc failed");
        xfree(msg_reply);
        return NULL;
    }
    rsp = (struct dt_rsp_loglevel *)(msg_reply->buf);

    if (msg->header.buf_size < sizeof(struct dt_req_loglevel)) {
        rsp->retval = -1;
    } else {
        // operation:  0=get 1=set
        if (req->operation == 0) {
            rsp->cur_loglevel = get_loglevel();
            rsp->retval = 0;
        } else if (req->operation == 1) {
            rsp->old_loglevel = get_loglevel();
            set_loglevel(req->loglevel);
            rsp->cur_loglevel = get_loglevel();
            rsp->retval = 0;
        } else {
            rsp->retval = -1;
        }
    }
    return msg_reply;
}

dt_message_t *process_node_msg(dt_message_t *msg)
{
    dt_message_t *msg_reply = NULL;

    switch (msg->header.cmd) {
    case CMD_REQ_PING:
        msg_reply = process_ping_msg(msg);
        break;
    case CMD_REQ_LOGLEVEL:
        msg_reply = process_loglevel_msg(msg);
        break;
    default:
        break;
    }

    return msg_reply;
}
