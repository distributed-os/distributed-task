#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dtt.h"
#include "modules.h"
#include "common.h"
#include "helper.h"

static void fill_ping_output(char *output, int len)
{
    snprintf(output, len,
            "%s"  "    \"changed\": false,"   "%s\n"
            "%s"  "    \"ping\": \"pong\""    "%s\n",
            COLOR_GREEN, COLOR_RESET,
            COLOR_GREEN, COLOR_RESET
            );
}

module_result_t module_ping(const char *ipv4)
{
    module_result_t res = {0};
    uint32_t ssid;
    int rc;

    res.rc = -1;
    res.changed = 0;

    if (ipv4_to_uint32(ipv4, &ssid) == 0) {
        rc = dt_ping((dt_ssid_t)ssid);
    } else {
        return res;
    }

    if (rc == 0) {
        res.rc = 0;
        res.output = calloc(1, BUF_SIZE_SMALL);
        fill_ping_output(res.output, BUF_SIZE_SMALL - 1);
    }
    return res;
}

module_result_t module_ssh_ping(const char *host)
{
    module_result_t res = {0};
    char cmd[BUF_SIZE_NORMAL];
    snprintf(cmd, sizeof(cmd),
            "ssh -o ConnectTimeout=10 -o BatchMode=yes -o StrictHostKeyChecking=no %s "
            "'python3 -c \"import json,sys; sys.stdout.write(json.dumps({\\\"ping\\\":\\\"pong\\\"}))\"' "
            "2>/dev/null",
            host);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        res.rc = -1;
        return res;
    }

    char buf[BUF_SIZE_SMALL];
    size_t n = fread(buf, 1, sizeof(buf)-1, fp);
    buf[n] = '\0';
    res.rc = WEXITSTATUS(pclose(fp));

    if (strstr(buf, "pong")) {
        res.output = calloc(1, BUF_SIZE_SMALL);
        fill_ping_output(res.output, BUF_SIZE_SMALL - 1);
        res.changed = 0;
    } else {
        res.rc = 255;
    }

    return res;
}
