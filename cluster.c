#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "dtt/transfer.h"
#include "dtt/discovery.h"
#include "log.h"
#include "dynarray.h"
#include "cluster.h"

#define CLUSTER_HOSTS_FILE  TMP_DIR "/cluster.hosts"
#define MIN_INTERVAL_SEC    1    /* 1 second */
#define MAX_INTERVAL_SEC    3600 /* 60 minutes */

// Thread control block
struct discovery_tcb {
    pthread_t thread;
    pthread_mutex_t lock;
    int running;
    struct dynarray node_list;
};

static struct discovery_tcb dt_tcb;

static int load_nodes_from_file(struct dynarray *node_list, const char *filename)
{
    FILE *fp = NULL;
    char line[256];
    int line_num = 0;
    int count = 0;

    if (!node_list) {
        pr_err("node_list is NULL\n");
        return -1;
    }

    fp = fopen(filename, "r");
    if (!fp) {
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        line_num++;

        /* Remove newline character */
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[--len] = '\0';
        }

        /* Skip empty lines and comments */
        if (len == 0 || line[0] == '#')
            continue;

        dt_node_t *node = calloc(1, sizeof(dt_node_t));
        if (!node) {
            pr_err("Failed to allocate memory for node at line %d\n", line_num);
            continue;
        }

        /* Parse format: ip hostname */
        int matched = sscanf(line, "%15s %63s", node->ip, node->hostname);
        if (matched != 2) {
            pr_warning("Invalid format at line %d, skipping\n", line_num);
            free(node);
            continue;
        }

        if (dynarray_append(node_list, node) < 0) {
            pr_err("Failed to append node at line %d\n", line_num);
            free(node);
            continue;
        }

        count++;
    }

    fclose(fp);
    return count;
}

static int write_nodes_to_file(struct dynarray *node_list, const char *filename)
{
    FILE *fp = NULL;
    char tmp_file[256];
    size_t i;

    snprintf(tmp_file, sizeof(tmp_file), "%s.tmp", filename);

    fp = fopen(tmp_file, "w");
    if (!fp) {
        pr_err("Failed to open temp file %s: %s\n", tmp_file, strerror(errno));
        return -1;
    }

    for (i = 0; i < dynarray_size(node_list); i++) {
        dt_node_t *node = dynarray_get(node_list, i);
        if (node) {
            fprintf(fp, "%s %s\n", node->ip, node->hostname);
        }
    }

    fclose(fp);

    if (rename(tmp_file, filename) != 0) {
        pr_err("Failed to rename %s to %s: %s\n", tmp_file, filename, strerror(errno));
        unlink(tmp_file);
        return -1;
    }

    pr_info("Updated cluster hosts file: %s\n", filename);
    return 0;
}

static int compare_node_list(struct dynarray *old_list, struct dynarray *new_list)
{
    size_t old_size, new_size, i, j;
    dt_node_t *old_node, *new_node;

    old_size = dynarray_size(old_list);
    new_size = dynarray_size(new_list);

    if (old_size != new_size)
        return 1;

    for (i = 0; i < new_size; i++) {
        new_node = dynarray_get(new_list, i);
        int found = 0;

        for (j = 0; j < old_size; j++) {
            old_node = dynarray_get(old_list, j);
            if (strcmp(old_node->ip, new_node->ip) == 0 &&
                strcmp(old_node->hostname, new_node->hostname) == 0) {
                found = 1;
                break;
            }
        }

        if (!found)
            return 1;
    }

    return 0;
}

static void free_node_array(struct dynarray *nodes)
{
    size_t i;
    for (i = 0; i < dynarray_size(nodes); i++) {
        dt_node_t *node = dynarray_get(nodes, i);
        if (node) {
            free(node);
        }
    }
    dynarray_destroy(nodes);
}

static void *discovery_node_thread(void *arg)
{
    (void) arg;
    int interval = MIN_INTERVAL_SEC;
    struct dynarray new_list = { 0 };
    size_t i;

    pr_info("Discovery thread started, initial interval: %d seconds\n", interval);

    pthread_mutex_lock(&dt_tcb.lock);
    load_nodes_from_file(&dt_tcb.node_list, CLUSTER_HOSTS_FILE);
    pthread_mutex_unlock(&dt_tcb.lock);

    while (dt_tcb.running) {
        sleep(interval);

        if (!dt_tcb.running)
            break;

        pr_debug("Running discovery check (interval: %d seconds)\n", interval);

        memset(&new_list, 0, sizeof(struct dynarray));
        int count = client_discovery(&new_list);

        if (count < 0) {
            pr_err("Discovery failed\n");
            free_node_array(&new_list);
            continue;
        }

        pr_debug("Discovery found %d nodes\n", count);

        pthread_mutex_lock(&dt_tcb.lock);

        if (compare_node_list(&dt_tcb.node_list, &new_list)) {
            pr_info("Cluster configuration changed, updating file\n");

            free_node_array(&dt_tcb.node_list);
            memset(&dt_tcb.node_list, 0, sizeof(struct dynarray));

            for (i = 0; i < dynarray_size(&new_list); i++) {
                dt_node_t *node = dynarray_get(&new_list, i);
                dt_node_t *new_node = malloc(sizeof(dt_node_t));
                if (new_node) {
                    memcpy(new_node, node, sizeof(dt_node_t));
                    dynarray_append(&dt_tcb.node_list, new_node);
                }
            }

            write_nodes_to_file(&dt_tcb.node_list, CLUSTER_HOSTS_FILE);
        }
        interval = (interval * 2 > MAX_INTERVAL_SEC) ? MAX_INTERVAL_SEC : interval * 2;

        pthread_mutex_unlock(&dt_tcb.lock);
        free_node_array(&new_list);
    }

    pr_info("Discovery thread exiting\n");
    return NULL;
}

int node_discovery_start(void)
{
    int ret;

    if (dt_tcb.running) {
        pr_warning("Discovery thread already running\n");
        return 0;
    }

    memset(&dt_tcb.node_list, 0, sizeof(struct dynarray));
    dt_tcb.running = 1;

    ret = pthread_mutex_init(&dt_tcb.lock, NULL);
    if (ret != 0) {
        pr_err("Failed to init mutex: %s\n", strerror(ret));
        return -1;
    }

    ret = pthread_create(&dt_tcb.thread, NULL, discovery_node_thread, NULL);
    if (ret != 0) {
        pr_err("Failed to create discovery thread: %s\n", strerror(ret));
        pthread_mutex_destroy(&dt_tcb.lock);
        dt_tcb.running = 0;
        return -1;
    }

    pthread_detach(dt_tcb.thread);
    return 0;
}

void node_discovery_stop(void)
{
    if (!dt_tcb.running)
        return;

    pr_info("Stopping discovery thread\n");

    dt_tcb.running = 0;

    pthread_mutex_lock(&dt_tcb.lock);
    free_node_array(&dt_tcb.node_list);
    pthread_mutex_unlock(&dt_tcb.lock);

    pthread_mutex_destroy(&dt_tcb.lock);

    memset(&dt_tcb, 0, sizeof(dt_tcb));
}

int manual_node_discovery(void)
{
    struct dynarray new_list = { 0 };
    int ret = 0;
    size_t i;

    int count = client_discovery(&new_list);
    if (count < 0) {
        pr_err("Manual discovery failed\n");
        ret = -1;
        goto out;
    }

    pthread_mutex_lock(&dt_tcb.lock);

    if (compare_node_list(&dt_tcb.node_list, &new_list)) {
        pr_info("Manual discovery: updating file\n");

        free_node_array(&dt_tcb.node_list);
        memset(&dt_tcb.node_list, 0, sizeof(struct dynarray));

        for (i = 0; i < dynarray_size(&new_list); i++) {
            dt_node_t *node = dynarray_get(&new_list, i);
            dt_node_t *new_node = malloc(sizeof(dt_node_t));
            if (new_node) {
                memcpy(new_node, node, sizeof(dt_node_t));
                dynarray_append(&dt_tcb.node_list, new_node);
            }
        }

        write_nodes_to_file(&dt_tcb.node_list, CLUSTER_HOSTS_FILE);
    } else {
        pr_info("Manual discovery: no changes\n");
    }

    pthread_mutex_unlock(&dt_tcb.lock);

out:
    free_node_array(&new_list);
    return ret;
}

struct dynarray *get_cluster_nodes()
{
    struct dynarray *nodes;
    size_t i;

    if (!dt_tcb.running)
        return NULL;

    nodes = calloc(1, sizeof(struct dynarray));
    if (!nodes)
        return NULL;

    pthread_mutex_lock(&dt_tcb.lock);

    for (i = 0; i < dynarray_size(&dt_tcb.node_list); i++) {
        dt_node_t *node = dynarray_get(&dt_tcb.node_list, i);
        dt_node_t *new_node = malloc(sizeof(dt_node_t));
        if (new_node) {
            memcpy(new_node, node, sizeof(dt_node_t));
            dynarray_append(nodes, new_node);
        }
    }

    pthread_mutex_unlock(&dt_tcb.lock);

    return nodes;
}

