#ifndef __OUTPUT_H__
#define __OUTPUT_H__

void print_host_list(void);
void print_success(const char *host, const char *msg);
void print_changed(const char *host, int rc, const char *output);
void print_failed(const char *host, int rc, const char  *output);
void print_unreachable(const char *host);

#endif
