#ifndef __CLUSTER_H__
#define __CLUSTER_H__

#include "dynarray.h"

int node_discovery_start(void);
void node_discovery_stop(void);
int manual_node_discovery(void);
struct dynarray *get_cluster_nodes(void);

#endif
