#include <stdio.h>
#include <string.h>

#include "inventory.h"
#include "output.h"
#include "common.h"

void print_host_list(void)
{
    int nr_host = get_host_count();
    struct host_info *host;
    printf("  hosts (%d):\n", nr_host);
    for (int i = 0; i < nr_host; i++) {
        host = get_host_at(i);
        if (host->hostname && strlen(host->hostname) > 0) {
            printf("    %s", host->hostname);
        }
        if (strlen(host->ipv4) > 0) {
            printf("    %s", host->ipv4);
        }
        printf("\n");
    }
}

void print_success(const char *host, const char *msg)
{
    printf("%s%s | SUCCESS => {%s\n%s%s}%s\n",
           COLOR_GREEN, host, COLOR_RESET, msg, COLOR_GREEN, COLOR_RESET);
}

void print_changed(const char *host, int rc, const char *output)
{
    printf("%s%s | CHANGED | rc=%d >>%s\n", COLOR_YELLOW, host, rc, COLOR_RESET);

    FILE *fp = fmemopen((void *)output, strlen(output), "r");

    char line[1024] = { 0 };
    while (fgets(line, sizeof(line) - 1, fp) != NULL) {
        line[strcspn(line, "\n")] = 0;
        printf("%s%s%s\n", COLOR_YELLOW, line, COLOR_RESET);
        memset(line, 0, sizeof(line));
    }

    fclose(fp);
}

void print_failed(const char *host, int rc, const char *output)
{
    printf("%s%s | FAILED | rc=%d >>%s\n", COLOR_RED, host, rc, COLOR_RESET);

    FILE *fp = fmemopen((void *)output, strlen(output), "r");

    char line[1024] = { 0 };
    while (fgets(line, sizeof(line) - 1, fp) != NULL) {
        line[strcspn(line, "\n")] = 0;
        printf("%s%s%s\n", COLOR_RED, line, COLOR_RESET);
        memset(line, 0, sizeof(line));
    }

    fclose(fp);
}

void print_unreachable(const char *host)
{
    printf("%s%s | UNREACHABLE! => {%s\n    \"unreachable\": true%s\n}%s\n",
           COLOR_RED, host, COLOR_RESET, COLOR_RED, COLOR_RESET);
}
