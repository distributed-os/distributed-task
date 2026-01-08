#ifndef __INVENTORY_H__
#define __INVENTORY_H__

#include "common.h"

struct host_info {
    char ipv4[16];
    char *hostname;
};

void parse_inventory(const char *file, const char *pattern);
int get_host_count();
struct host_info* get_host_at(int idx);

#endif
