#ifndef __SNODE_H__
#define __SNODE_H__

#include <stdint.h>

int64_t available_load_capacity();
dt_message_t *process_node_msg(dt_message_t *msg);

#endif
