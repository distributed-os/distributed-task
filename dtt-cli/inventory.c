#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>

#include "inventory.h"
#include "common.h"

static struct host_info hosts[MAX_HOSTS] = { 0 };
static int host_count = 0;

int get_host_count()
{
    return host_count;
}

struct host_info* get_host_at(int idx)
{
    if (idx < 0 || idx >= host_count) {
        return NULL;
    }
    return &hosts[idx];
}

static void parse_dtts_conf(const char *file, const char *pattern)
{
    FILE *fp = fopen(file, "r");
    if (fp == NULL) {
        return;
    }

    char line[256];
    bool match_all = (strcmp(pattern, "all") == 0);

    while (fgets(line, sizeof(line), fp) != NULL && host_count < MAX_HOSTS) {
        if (line[0] == '\n' || line[0] == '#') {
            continue;
        }

        line[strcspn(line, "\n")] = '\0';

        char ip[16];
        char hostname[128];

        if (sscanf(line, "%15s %127s", ip, hostname) == 2) {
            if (match_all ||
                strcmp(ip, pattern) == 0 ||
                strcmp(hostname, pattern) == 0) {

                strncpy(hosts[host_count].ipv4, ip, sizeof(hosts[host_count].ipv4));
                hosts[host_count].ipv4[sizeof(hosts[host_count].ipv4) - 1] = '\0';

                hosts[host_count].hostname = strdup(hostname);
                if (hosts[host_count].hostname == NULL) {
                    continue;
                }

                host_count++;

                if (!match_all) {
                    break;
                }
            }
        }
    }

    fclose(fp);
}

static void parse_cluster_conf(const char *file, const char *pattern)
{
    FILE *fp = NULL;
    char line[256];
    char *trimmed_line;
    int i;

    fp = fopen(file, "r");
    if (fp == NULL) {
        return;
    }

    while (fgets(line, sizeof(line), fp) != NULL && host_count < MAX_HOSTS) {
        line[strcspn(line, "\n")] = '\0';

        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }

        trimmed_line = line;
        while (isspace((unsigned char)*trimmed_line)) trimmed_line++;

        i = strlen(trimmed_line);
        while (i > 0 && isspace((unsigned char)trimmed_line[i - 1])) {
            trimmed_line[--i] = '\0';
        }

        if (trimmed_line[0] == '\0') {
            continue;
        }

        // Pattern is all
        if (strcmp(pattern, "all") == 0) {
            // Read all lines
            hosts[host_count].hostname = malloc(strlen(trimmed_line) + 1);
            if (hosts[host_count].hostname != NULL) {
                strcpy(hosts[host_count].hostname, trimmed_line);
                host_count++;
            }
        } else {
            if (strcmp(trimmed_line, pattern) == 0) {
                hosts[host_count].hostname = malloc(strlen(trimmed_line) + 1);
                if (hosts[host_count].hostname != NULL) {
                    strcpy(hosts[host_count].hostname, trimmed_line);
                    host_count++;
                }
                break;
            }
        }
    }

    fclose(fp);
}

static void parse_ansible_hosts(const char *file, const char *pattern)
{
    FILE *f = fopen(file, "r");
    if (!f) {
        return;
    }

    char line[MAX_LINE];
    int in_target_group = 0;
    int match_all = (strcmp(pattern, "all") == 0);

    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = 0;
        char *p = line;
        while (isspace(*p)) p++;
        if (*p == '\0' || *p == '#') continue;

        if (*p == '[') {
            char *end = strchr(p, ']');
            if (!end) continue;
            *end = '\0';
            char *group_name = p + 1;

            // Handle group names that may contain colons (e.g., [group:children])
            char *colon = strchr(group_name, ':');
            if (colon) *colon = '\0';

            if (match_all) {
                in_target_group = 1;
            } else {
                // Exact match for group name
                in_target_group = (strcmp(group_name, pattern) == 0);
            }
            continue;
        }

        if (!in_target_group && !match_all) {
            // If not in target group, check if hostname matches directly
            char *host = strtok(p, " \t");
            if (host && strcmp(host, pattern) == 0) {
                if (host_count < MAX_HOSTS) {
                    hosts[host_count++].hostname = strdup(host);
                }
            }
            continue;
        }

        // Process host line
        char *host = strtok(p, " \t");
        if (!host) continue;

        // Skip lines starting with digits (might be IP addresses)
        if (isdigit(*host)) continue;

        // Check for variable assignments (e.g., ansible_host=xxx)
        if (strchr(host, '=')) continue;

        if (host_count < MAX_HOSTS) {
            hosts[host_count++].hostname = strdup(host);
        }
    }
    fclose(f);
}

void parse_inventory(const char *file, const char *pattern)
{
    if (access(file, F_OK) == 0) {
        parse_ansible_hosts(file, pattern);
    } else if (access(DEFAULT_CLUSTER_CONF, F_OK) == 0) {
        parse_cluster_conf(DEFAULT_CLUSTER_CONF, pattern);
    } else if (access(DEFAULT_DTTS_CONF, F_OK) == 0) {
        parse_dtts_conf(DEFAULT_DTTS_CONF, pattern);
    }
}
