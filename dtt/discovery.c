#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>

#include "log.h"
#include "dynarray.h"
#include "transfer.h"
#include "discovery.h"

int client_discovery(struct dynarray *node_list)
{
    int sockfd;
    struct sockaddr_in multicast_addr;
    discovery_message_t msg = { 0 };
    struct timeval tv;

    // Create UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        return -1;
    }

    // Set socket option to allow broadcast
    int broadcast = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) < 0) {
        close(sockfd);
        return -1;
    }

    // Set receive timeout
    tv.tv_sec = TIMEOUT_MS / 1000;
    tv.tv_usec = (TIMEOUT_MS % 1000) * 1000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Set multicast address
    memset(&multicast_addr, 0, sizeof(multicast_addr));
    multicast_addr.sin_family = AF_INET;
    multicast_addr.sin_addr.s_addr = inet_addr(MULTICAST_GROUP);
    multicast_addr.sin_port = htons(DISCOVERY_PORT);

    // Prepare discovery request
    msg.type = MSG_DISCOVERY_REQUEST;
    msg.service_port = htons(TRANS_PORT);

    // Send discovery request to multicast group
    if (sendto(sockfd, &msg, sizeof(msg), 0,
               (struct sockaddr*)&multicast_addr, sizeof(multicast_addr)) < 0) {
        close(sockfd);
        return -1;
    }

    // Receive responses
    while (1) {
        struct sockaddr_in from_addr;
        socklen_t addr_len = sizeof(from_addr);
        discovery_message_t response = { 0 };

        int n = recvfrom(sockfd, &response, sizeof(response), 0,
                        (struct sockaddr*)&from_addr, &addr_len);

        if (n < 0) {
            // Timeout or other error
            break;
        }

        if (n == sizeof(response) && response.type == MSG_DISCOVERY_RESPONSE) {
            dt_node_t *node = calloc(1, sizeof(dt_node_t));
            strncpy(node->ip, response.service_ip, sizeof(response.service_ip));
            strncpy(node->hostname, response.host_name, sizeof(response.host_name));
            node->avail_load = (float)response.avail_load / 100.0;
            dynarray_append(node_list, node);
        }
    }

    close(sockfd);
    return dynarray_size(node_list);
}
