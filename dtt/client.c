#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/uio.h>
#include <arpa/inet.h>

#include "util.h"
#include "crc.h"
#include "helper.h"
#include "transfer.h"

int recv_reply(int client_socket, dt_message_t *reply)
{
    struct dt_message_header header;
    uint16_t crc;

    if (!reply)
        return -1;

    ssize_t num_bytes = xread(client_socket, &header, sizeof(struct dt_message_header));
    if (num_bytes < 0) {
        return -1;
    }

    crc = crc16(0, (const uint8_t *)&header, offsetof(struct dt_message_header, crc));
    if (crc != header.crc) {
        return -1;
    }

    memcpy(&reply->header, &header, sizeof(struct dt_message_header));

    if (reply->header.buf_size > 0 && reply->header.buf_size > reply->header.data_len) {
        reply->buf = xmalloc(reply->header.buf_size - reply->header.data_len);
        num_bytes = xread(client_socket, reply->buf, reply->header.buf_size - reply->header.data_len);
        if (num_bytes < 0) {
            return -1;
        }

        if (reply->data && reply->header.data_len) {
            num_bytes = xread(client_socket, reply->data, reply->header.data_len);
            if (num_bytes < 0) {
                return -1;
            }
        }
    }

    return 0;
}

static int client_connect(dt_node_t *node)
{
    int sock = 0;
    struct sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(TRANS_PORT);

    if (inet_pton(AF_INET, node->ip, &serv_addr.sin_addr) <= 0) {
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        return -1;
    }

    return sock;
}

static void client_disconnect(int sock)
{
    close(sock);
}

int client_send(dt_node_t *node, dt_message_t *msg, dt_message_t *reply)
{
    int sock = 0;

    if (!msg || !reply)
        return -1;

    sock = client_connect(node);
    if (sock < 0) {
        return -1;
    }

    msg->header.crc = crc16(0, (const uint8_t *)&msg->header,
            offsetof(struct dt_message_header, crc));

    if (msg->header.buf_size < 64 * 1024 * 1024) { // Less than 64MB
        struct iovec iov[3];
        int iov_count;
        ssize_t bytes_written;

        iov[0].iov_base = (char *)&msg->header;
        iov[0].iov_len = sizeof(struct dt_message_header);
        iov[1].iov_base = msg->buf;
        iov[1].iov_len = msg->header.buf_size - msg->header.data_len;
        iov_count = 2;
        if (msg->data && msg->header.data_len > 0) {
            iov[2].iov_base = msg->data;
            iov[2].iov_len = msg->header.data_len;
            iov_count = 3;
        }

        bytes_written = writev(sock, iov, iov_count);
        if (bytes_written < 0) {
            // Handle write error
            client_disconnect(sock);
            return -1;
        }
    } else {
        xwrite(sock, (const char *)&msg->header, sizeof(struct dt_message_header));
        xwrite(sock, msg->buf, msg->header.buf_size - msg->header.data_len);
        if (msg->data && msg->header.data_len > 0) {
            xwrite(sock, msg->data, msg->header.data_len);
        }
    }

    recv_reply(sock, reply);
    client_disconnect(sock);
    return 0;
}
