#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

#include "dtt.h"
#include "executor.h"
#include "inventory.h"
#include "output.h"
#include "modules.h"
#include "common.h"
#include "helper.h"
#include "is.h"

typedef struct {
    const char *module_name;
    const char *args;
    const char *host;
} module_task_t;

void *run_task(void *arg)
{
    module_task_t *t = (module_task_t *)arg;
    module_result_t res = {0};
    char ipv4[16] = { 0 };
    bool use_ssh = true;
    uint32_t ssid = 0;

    if (is_valid_ipv4(t->host)) {
        strcpy(ipv4, t->host);
    } else {
        hostname_to_ipv4(t->host, ipv4, sizeof(ipv4));
    }

    if (ipv4_to_uint32(ipv4, &ssid) == 0) {
        if (dt_ping((dt_ssid_t)ssid) == 0) {
            use_ssh = false;
        }
    }

    if (strcmp(t->module_name, "ping") == 0) {
        if (use_ssh) {
           res = module_ssh_ping(ipv4);
        } else {
           res = module_ping(ipv4);
        }
    } else if (strcmp(t->module_name, "command") == 0) {
        if (use_ssh) {
            res = module_ssh_command(ipv4, t->args);
        } else {
            res = module_command(ipv4, t->args);
        }
    } else if (strcmp(t->module_name, "copy") == 0) {
        // Parse src and dest (example: args="src=/a dest=/b")
        char src[MAX_PATH] = {0}, dest[MAX_PATH] = {0};
        char *p = strstr(t->args, "src=");
        if (p) sscanf(p, "src=%4095[^ ]", src);
        p = strstr(t->args, "dest=");
        if (p) sscanf(p, "dest=%4095s", dest);
        if (use_ssh) {
            res = module_ssh_copy(ipv4, src[0] ? src : "/tmp/test", dest[0] ? dest : "/tmp/");
        } else {
            res = module_copy(ipv4, src[0] ? src : "/tmp/test", dest[0] ? dest : "/tmp/");
        }
    } else {
        print_failed(t->host, 1, "");
        free(t);
        return NULL;
    }

    if (res.rc == 255 || res.rc == -1) {
        print_unreachable(t->host);
    } else if (res.rc == 0) {
        if (res.changed) {
            print_changed(t->host, res.rc, res.output ? res.output : "");
        } else {
            print_success(t->host, res.output ? res.output : "\"msg\": \"ok\"");
        }
    } else {
        print_failed(t->host, res.rc, res.output ? res.output : "");
    }

    if (res.output) free(res.output);
    free(t);
    return NULL;
}

void execute_tasks(const char *module_name, const char *args, int forks)
{
    pthread_t threads[MAX_HOSTS];
    int active = 0;
    struct host_info *host;

    for (int i = 0; i < get_host_count(); i++) {
        module_task_t *t = malloc(sizeof(module_task_t));
        t->module_name = module_name;
        t->args = args;

        host = get_host_at(i);
        if (strlen(host->ipv4) > 0) {
            t->host = host->ipv4;
        } else {
            t->host = host->hostname;
        }

        pthread_create(&threads[active], NULL, run_task, t);
        active++;

        if (active >= forks) {
            for (int j = 0; j < active; j++) {
                pthread_join(threads[j], NULL);
            }
            active = 0;
        }
    }

    for (int j = 0; j < active; j++) {
        pthread_join(threads[j], NULL);
    }
}
