# Distributed-Task

A high-performance distributed computing framework written in C, enabling thread-level task scheduling, unified memory access, and distributed file operations across cluster nodes.

## Overview

Distributed-Task is a lightweight yet powerful framework that provides distributed computing capabilities with a focus on performance and ease of use. It allows developers to write distributed applications as if they were running on a single machine, while automatically leveraging the power of multiple nodes in a cluster.

## Key Features

### 1. **Distributed Task Scheduling**
- Thread-level task distribution across cluster nodes
- Simple API for task creation and management
- Automatic load balancing and task coordination

```c
#include "dtt.h"

int id = dt_task_create(0, task, NULL, NULL);
dt_join(id);
```

### 2. **Unified Memory Access**
- Single address space across the entire cluster
- Transparent access to remote memory regions
- Consistent memory semantics across distributed nodes

```c
#include "dtt.h"

dt_addr_t *addr = dt_malloc(0, 128);
dt_free(addr);
```

### 3. **Distributed File Operations**
- POSIX-like interface for cluster-wide file access
- Access any file on any node from any location
- Consistent file operations across distributed storage

```c
#include "dtt.h"

int result = dt_file_write(0, file, offset, size, buf);
int result = dt_file_read(0, file, offset, size, buf);
```

### 4. **Ansible-Compatible CLI Tool (`dtt`)**
- **Zero-deployment**: Automatic cluster discovery
- **High performance**: 10x faster than Ansible in benchmarks
- **Module support**: ping, command, copy modules (extensible)

```bash
# ./dtt-cli/dtt all -m ping
# ./dtt-cli/dtt webservers -m command -a "uptime"
```

## Quick Start

- For RPM-based systems (CentOS/RHEL/Fedora):
```bash
# make rpm && rpm -ivh *.rpm
```

- For DEB-based systems (Ubuntu/Debian):
```bash
# make deb && dpkg -i *.deb
```

## Building and Running from Source
```bash
# make && ./dtts
```
---

*Note: This framework is under active development. Features and APIs may evolve based on community feedback and requirements.*
