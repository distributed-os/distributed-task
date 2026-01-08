#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <ifaddrs.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "dtt.h"
#include "helper.h"
#include "util.h"
#include "crc.h"
#include "log.h"
#include "dtt/transfer.h"
#include "dtt/discovery.h"
#include "node.h"
#include "file.h"
#include "memory.h"
#include "task.h"
#include "cluster.h"

// Global variable to control thread
static volatile int discovery_running = 0;
static pthread_t discovery_thread;

static int is_lan_ip(const char* ip)
{
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) return 0;

    unsigned int ip_int = ntohl(addr.s_addr);
    return ((ip_int >= 0x0A000000) && (ip_int <= 0x0AFFFFFF)) ||
        ((ip_int >= 0xAC100000) && (ip_int <= 0xAC1FFFFF)) ||
        ((ip_int >= 0xC0A80000) && (ip_int <= 0xC0A8FFFF));
}

static char* get_hostname()
{
    static char hostname[64] = { 0 };

    if (gethostname(hostname, sizeof(hostname)) != 0) {
        return "localhost";
    }

    return hostname;
}

static char* get_local_ip()
{
    static char ip[16] = "127.0.0.1";
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) return ip;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET)
            continue;

        struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
        char *current_ip = inet_ntoa(sa->sin_addr);

        if (strcmp(ifa->ifa_name, "lo") == 0 ||
                strncmp(ifa->ifa_name, "vnet", 4) == 0 ||
                strncmp(ifa->ifa_name, "veth", 4) == 0 ||
                strncmp(ifa->ifa_name, "docker", 6) == 0) {
            continue;
        }

        if (is_lan_ip(current_ip)) {
            strncpy(ip, current_ip, sizeof(ip) - 1);
            break;
        }
    }

    freeifaddrs(ifaddr);
    return ip;
}

static void* service_discovery_thread(void* arg)
{
    (void) arg;
    int sockfd;
    struct sockaddr_in addr;
    discovery_message_t msg = { 0 };
    socklen_t addr_len = sizeof(addr);

    // Create UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        return NULL;
    }

    // Set socket options
    int reuse = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt SO_REUSEADDR");
        close(sockfd);
        return NULL;
    }

    // Bind to discovery port
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(DISCOVERY_PORT);

    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sockfd);
        return NULL;
    }

    // Join multicast group
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_GROUP);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    if (setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt IP_ADD_MEMBERSHIP");
        close(sockfd);
        return NULL;
    }

    discovery_running = 1;
    while (discovery_running) {
        fd_set readfds;
        struct timeval tv;

        // Set file descriptor set
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);

        // Set timeout (1 second)
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        // Use select to implement timeout checking, allowing periodic checks of discovery_running
        int ret = select(sockfd + 1, &readfds, NULL, NULL, &tv);

        if (ret < 0) {
            perror("select");
            break;
        } else if (ret == 0) {
            // Timeout, continue loop to check running flag
            continue;
        }

        // Data available to read
        if (FD_ISSET(sockfd, &readfds)) {
            int n = recvfrom(sockfd, &msg, sizeof(msg), 0, (struct sockaddr*)&addr, &addr_len);

            if (n == sizeof(msg) && msg.type == MSG_DISCOVERY_REQUEST) {
                pr_debug("Discovery recv %s:%d", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
                // Prepare response message
                msg.type = MSG_DISCOVERY_RESPONSE;
                msg.service_port = htons(TRANS_PORT);
                strncpy(msg.service_ip, get_local_ip(), sizeof(msg.service_ip));
                strncpy(msg.host_name, get_hostname(), sizeof(msg.host_name));
                msg.avail_load = available_load_capacity();

                // Send response
                sendto(sockfd, &msg, sizeof(msg), 0, (struct sockaddr*)&addr, addr_len);
            }
        }
    }

    close(sockfd);
    return NULL;
}

// Start the service discovery thread
static int service_discovery_start()
{
    if (discovery_running) {
        return -1;
    }

    int ret = pthread_create(&discovery_thread, NULL, service_discovery_thread, NULL);
    if (ret != 0) {
        return -1;
    }

    // Set thread to detached state so no join is needed
    pthread_detach(discovery_thread);
    return 0;
}

// Stop the service discovery
static void service_discovery_stop()
{
    if (discovery_running) {
        discovery_running = 0;
    }
}

static void process_msg(int client_socket, dt_message_t *msg)
{
    dt_message_t *msg_reply = NULL;

    if (!msg)
        return;

    if (msg->header.cmd & CMD_NODE_BASE) {
        msg_reply = process_node_msg(msg);
    } else if (msg->header.cmd & CMD_TASK_BASE) {
        msg_reply = process_task_msg(msg);
    } else if (msg->header.cmd & CMD_FILE_BASE) {
        msg_reply = process_file_msg(msg);
    } else if (msg->header.cmd & CMD_MEMORY_BASE) {
        msg_reply = process_memory_msg(msg);
    }

    if (msg_reply) {
        msg_reply->header.crc = crc16(0, (const uint8_t *)&msg_reply->header,
                offsetof(struct dt_message_header, crc));
        if (msg_reply->header.buf_size < 64 * 1024 * 1024) { // Less than 64MB
            struct iovec iov[3];
            int iov_count;
            iov[0].iov_base = (char *)&msg_reply->header;
            iov[0].iov_len = sizeof(struct dt_message_header);
            iov[1].iov_base = msg_reply->buf;
            iov[1].iov_len = msg_reply->header.buf_size - msg_reply->header.data_len;
            iov_count = 2;
            if (msg_reply->data && msg_reply->header.data_len > 0) {
                iov_count = 3;
                iov[2].iov_base = msg_reply->data;
                iov[2].iov_len = msg_reply->header.data_len;
            }

            if (writev(client_socket, iov, iov_count) < 0) {
                pr_err("writev failed");
            }
        } else {
            xwrite(client_socket, (const char *)&msg_reply->header,
                    sizeof(struct dt_message_header));
            xwrite(client_socket, msg_reply->buf,
                    msg_reply->header.buf_size - msg_reply->header.data_len);
            if (msg_reply->data && msg_reply->header.data_len > 0) {
                xwrite(client_socket, msg_reply->data, msg_reply->header.data_len);
            }
        }

        xfree(msg_reply->data);
        xfree(msg_reply->buf);
        xfree(msg_reply);
    }
}

static void *handle_client_thread(void *arg)
{
    dt_message_t *receive = NULL;
    uint16_t crc;
    int client_socket = *(int *)arg;
    free(arg);  // Free memory allocated in the main thread

    struct dt_message_header header;
    ssize_t num_bytes = xread(client_socket, &header, sizeof(struct dt_message_header));
    if (num_bytes <= 0) {
        if (num_bytes < 0)
            perror("recv header failed");
        goto cleanup;
    }

    crc = crc16(0, (const uint8_t *)&header, offsetof(struct dt_message_header, crc));
    if (crc != header.crc) {
        pr_err("crc verification failed 0x%X != 0x%X", crc, header.crc);
        goto cleanup;
    }

    receive = xmalloc(sizeof(dt_message_t));
    if (!receive) {
        perror("malloc failed");
        goto cleanup;
    }
    memcpy(&receive->header, &header, sizeof(struct dt_message_header));

    receive->buf = xmalloc(header.buf_size);
    if (!receive->buf) {
        perror("malloc failed");
        goto cleanup;
    }

    if (receive->header.buf_size > 0) {
        num_bytes = xread(client_socket, receive->buf, receive->header.buf_size);
        if (num_bytes <= 0) {
            if (num_bytes < 0)
                perror("recv buffer failed");
            free(receive);
            goto cleanup;
        }
    }

    process_msg(client_socket, receive);

cleanup:
    if (receive)
       xfree(receive->buf);
    xfree(receive);
    close(client_socket);
    return NULL;
}

static int create_directory(const char *path)
{
    struct stat st;
    mode_t mode = 0755;

    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return 0;
        } else {
            errno = ENOTDIR;
            return -1;
        }
    }

    if (mkdir(path, mode) == 0) {
        return 0;
    } else {
        return -1;
    }
}

int main()
{
    int server_fd, *client_socket_ptr;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    pthread_t thread_id;

    create_directory(TMP_DIR);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(TRANS_PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 128) < 0) {  // Backlog can be set larger
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    // Start automatic discovery service
    service_discovery_start();

    // Start cluster node self-discovery
    node_discovery_start();

    pr_info("Service dtts listening on port %d ...", TRANS_PORT);

    while (1) {
        client_socket_ptr = malloc(sizeof(int));
        if (!client_socket_ptr) {
            perror("malloc failed for client socket");
            continue;
        }

        *client_socket_ptr = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (*client_socket_ptr < 0) {
            perror("accept failed");
            free(client_socket_ptr);
            continue;
        }

        // Create a thread to handle this client
        if (pthread_create(&thread_id, NULL, handle_client_thread, client_socket_ptr) != 0) {
            perror("pthread_create failed");
            close(*client_socket_ptr);
            free(client_socket_ptr);
            continue;
        }

        // Detach the thread to avoid manual join and prevent thread handle leaks
        pthread_detach(thread_id);
    }

    node_discovery_stop();
    service_discovery_stop();
    close(server_fd);
    return 0;
}
