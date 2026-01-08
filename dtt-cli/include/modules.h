#ifndef __MODULES_H__
#define __MODULES_H__

typedef struct {
    char *output;
    int rc;
    int changed;
} module_result_t;

module_result_t module_ping(const char *ipv4);
module_result_t module_ssh_ping(const char *host);

module_result_t module_command(const char *ipv4, const char *args);
module_result_t module_ssh_command(const char *host, const char *args);

module_result_t module_copy(const char *ipv4, const char *src, const char *dest);
module_result_t module_ssh_copy(const char *host, const char *src, const char *dest);

#endif
