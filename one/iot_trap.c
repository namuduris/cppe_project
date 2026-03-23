#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define LISTEN_PORT 9999
#define RECV_BUF_SIZE 1024
#define CMD_BUF_SIZE 64
#define LOG_FILE "iot_trap.log"

static volatile sig_atomic_t keep_running = 1;

static void handle_sigint(int sig)
{
    (void) sig;
    keep_running = 0;
}

static void build_timestamp(char *out, size_t out_size)
{
    time_t now = time(NULL);
    struct tm tm_now;

    localtime_r(&now, &tm_now);
    strftime(out, out_size, "%Y-%m-%dT%H:%M:%S%z", &tm_now);
}

static void append_json_escaped(char *dst, size_t dst_size, const unsigned char *src, size_t src_len)
{
    size_t i;
    size_t used = strlen(dst);

    for (i = 0; i < src_len && used + 7 < dst_size; i++) {
        unsigned char c = src[i];

        if (c == '\\' || c == '"') {
            dst[used++] = '\\';
            dst[used++] = (char) c;
        }
        else if (c == '\n') {
            dst[used++] = '\\';
            dst[used++] = 'n';
        }
        else if (c == '\r') {
            dst[used++] = '\\';
            dst[used++] = 'r';
        }
        else if (c == '\t') {
            dst[used++] = '\\';
            dst[used++] = 't';
        }
        else if (isprint(c)) {
            dst[used++] = (char) c;
        }
        else {
            int written = snprintf(dst + used, dst_size - used, "\\u%04x", c);
            if (written < 0 || (size_t) written >= dst_size - used) {
                break;
            }
            used += (size_t) written;
        }
    }

    dst[used] = '\0';
}

static void log_payload_json(const struct sockaddr_in *client_addr, const unsigned char *payload, size_t payload_len)
{
    FILE *fp = fopen(LOG_FILE, "a");
    if (!fp) {
        perror("fopen log");
        return;
    }

    char timestamp[64] = {0};
    char escaped[RECV_BUF_SIZE * 6] = {0};
    char ip[INET_ADDRSTRLEN] = {0};

    build_timestamp(timestamp, sizeof(timestamp));
    inet_ntop(AF_INET, &(client_addr->sin_addr), ip, sizeof(ip));
    append_json_escaped(escaped, sizeof(escaped), payload, payload_len);

    fprintf(fp,
            "{\"timestamp\":\"%s\",\"src\":\"%s:%d\",\"payload\":\"%s\"}\n",
            timestamp,
            ip,
            ntohs(client_addr->sin_port),
            escaped);

    fclose(fp);
}

int main(void)
{
    int server_fd;
    struct sockaddr_in server_addr;

    signal(SIGINT, handle_sigint);
    signal(SIGTERM, handle_sigint);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    int reuse = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt");
        close(server_fd);
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(LISTEN_PORT);

    if (bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 8) < 0) {
        perror("listen");
        close(server_fd);
        return 1;
    }

    printf("[iot_trap] Mock smart bulb listening on TCP port %d\n", LISTEN_PORT);

    while (keep_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *) &client_addr, &client_len);

        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept");
            break;
        }

        unsigned char recv_buf[RECV_BUF_SIZE + 1];
        ssize_t n = recv(client_fd, recv_buf, RECV_BUF_SIZE, 0);
        if (n > 0) {
            recv_buf[n] = '\0';
            log_payload_json(&client_addr, recv_buf, (size_t) n);

            char command[CMD_BUF_SIZE];
            /* Deliberate vulnerability for simulation: unsafe copy with no bounds checks. */
            strcpy(command, (char *) recv_buf);

            if (strncmp(command, "ON", 2) == 0) {
                printf("[iot_trap] Bulb switched ON\n");
            }
            else if (strncmp(command, "OFF", 3) == 0) {
                printf("[iot_trap] Bulb switched OFF\n");
            }
            else if (strncmp(command, "STATUS", 6) == 0) {
                printf("[iot_trap] Bulb status requested\n");
            }
            else {
                printf("[iot_trap] Unknown command received\n");
            }

            send(client_fd, "OK\n", 3, 0);
        }

        close(client_fd);
    }

    close(server_fd);
    printf("[iot_trap] shutting down\n");
    return 0;
}
