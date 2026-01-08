#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "dtt.h"
#include "modules.h"
#include "common.h"
#include "helper.h"

static char *get_first_word(const char *str)
{
    if (str == NULL) return NULL;

    while (*str == ' ') str++;
    if (*str == '\0') return NULL;

    const char *end = str;
    while (*end != ' ' && *end != '\0') end++;

    size_t len = end - str;
    char *result = malloc(len + 1);
    if (result) {
        strncpy(result, str, len);
        result[len] = '\0';
    }
    return result;
}

static dt_ret_t *cmd_result_new()
{
    dt_ret_t *ret = malloc(sizeof(dt_ret_t));

    ret->result = 0;
    ret->outlen = BUF_SIZE_LARGE;
    ret->errlen = BUF_SIZE_NORMAL;

    ret->out = calloc(1, ret->outlen);
    ret->err = calloc(1, ret->errlen);

    return ret;
}

static void cmd_result_release(dt_ret_t *ret)
{
    if (!ret)
        return;

    if (ret->out)
        free(ret->out);

    if (ret->err)
        free(ret->err);

    free(ret);
}

module_result_t module_command(const char *ipv4, const char *args)
{
    module_result_t res = {0};
    int id;
    uint32_t ssid;
    dt_ret_t *ret;

    res.rc = -1;
    res.changed = 0;

    if (ipv4_to_uint32(ipv4, &ssid) == 0) {
        ret = cmd_result_new();
        id = dt_cmd_create(ssid, args, ret);
        if (id < 0) {
            return res;
        }
        dt_join(id);

        res.rc = ret->result;
        res.changed = 1;

        res.output = calloc(1, ret->outlen + ret->errlen + 1);
        if (strlen(ret->out) > 0) {
            strncpy(res.output, ret->out, ret->outlen + ret->errlen);
        }
        if (res.rc == 127) {
            res.rc = 2;
            char *first = get_first_word(args);
            snprintf(res.output + strlen(ret->out), ret->outlen - strlen(ret->out),
                    "[Errno 2] No such file or directory: b'%s'",
                    first == NULL ? "" : first);
            if (first) free(first);
        } else {
            if (strlen(ret->err) > 0) {
                strncpy(res.output + strlen(ret->out), ret->err,
                        ret->outlen + ret->errlen - strlen(ret->out));
            }
        }
        cmd_result_release(ret);
    }

    return res;
}

module_result_t module_ssh_command(const char *host, const char *args)
{
    module_result_t res = {0};
    char *cmd;
    char *escaped;
    const char *src = args ? args : "";
    char *dst;

    escaped = calloc(1, BUF_SIZE_LARGE);
    dst = escaped;
    while (*src) {
        if (*src == '\'') { *dst++ = '\''; *dst++ = '\\'; *dst++ = '\''; *dst++ = '\''; }
        else *dst++ = *src;
        src++;
    }

    cmd = calloc(1, BUF_SIZE_LARGE);
    snprintf(cmd, BUF_SIZE_LARGE - 1,
            "ssh -o ConnectTimeout=10 -o BatchMode=yes -o StrictHostKeyChecking=no %s '%s' 2>&1",
            host, escaped[0] ? escaped : "echo");

    FILE *fp = popen(cmd, "r");
    free(cmd);
    free(escaped);
    if (!fp) {
        res.rc = -1;
        return res;
    }

    res.output = calloc(1, BUF_SIZE_LARGE);
    size_t n = fread(res.output, 1, BUF_SIZE_LARGE - 1, fp);
    res.output[n] = '\0';
    res.rc = WEXITSTATUS(pclose(fp));
    if (res.rc == 127) {
        res.rc = 2;
        char *first = get_first_word(args);
        snprintf(res.output, BUF_SIZE_LARGE - 1,
                "[Errno 2] No such file or directory: b'%s'",
                first == NULL ? "" : first);
        if (first) free(first);
    }
    res.changed = (n > 0);

    return res;
}
