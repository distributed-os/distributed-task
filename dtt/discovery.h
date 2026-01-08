#ifndef __DISCOVERY_H__
#define __DISCOVERY_H__

#include "dynarray.h"

#define TIMEOUT_MS 1000
#define DISCOVERY_PORT 15944  // Multicast discovery protocol port
#define MULTICAST_GROUP "239.255.255.250"

// Discovery protocol message types
#define MSG_DISCOVERY_REQUEST  1
#define MSG_DISCOVERY_RESPONSE 2

// Protocol message structure
typedef struct {
    uint8_t type;
    uint16_t service_port;
    char service_ip[16];
    char host_name[64];
    int64_t avail_load;
} __attribute__((packed)) discovery_message_t;

int client_discovery(struct dynarray *darray);

#endif
