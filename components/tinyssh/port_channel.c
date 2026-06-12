#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_chip_info.h"
#include "esp_log.h"

#include "byte.h"
#include "bug.h"
#include "e.h"
#include "purge.h"
#include "connectioninfo.h"
#include "iptostr.h"
#include "porttostr.h"
#include "buf.h"
#include "str.h"
#include "trymlock.h"
#include "limit.h"
#include "channel.h"

#define TAG "port_channel"

struct channel channel = {0};

static int socketpair_tcp(int fds[2]) {
    int listener = -1;
    int client = -1;
    int accepted = -1;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0; // bind to random free port

    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) < 0) goto err;
    if (listen(listener, 1) < 0) goto err;
    if (getsockname(listener, (struct sockaddr *)&addr, &addr_len) < 0) goto err;

    client = socket(AF_INET, SOCK_STREAM, 0);
    if (client < 0) goto err;

    if (connect(client, (struct sockaddr *)&addr, sizeof(addr)) < 0) goto err;

    accepted = accept(listener, (struct sockaddr *)&addr, &addr_len);
    if (accepted < 0) goto err;

    close(listener);
    fds[0] = client;
    fds[1] = accepted;
    return 0;

err:
    if (listener >= 0) close(listener);
    if (client >= 0) close(client);
    if (accepted >= 0) close(accepted);
    return -1;
}

// Forward declaration of interpreter task
static void interpreter_task(void *pvParameters);

int channel_open(const char *user, crypto_uint32 id, crypto_uint32 remotewindow, crypto_uint32 maxpacket, crypto_uint32 *localwindow) {
    if (!localwindow) bug_inval();
    if (!maxpacket) bug_inval();
    if (!remotewindow) bug_inval();
    if (channel.maxpacket != 0) bug_proto();
    if (channel.pid != 0) bug_proto();

    if (!str_copyn(channel.user, sizeof channel.user, user)) bug_nomem();

    channel.id = id;
    channel.maxpacket    = maxpacket;
    channel.remotewindow = remotewindow;
    channel.localwindow  = *localwindow = CHANNEL_BUFSIZE;

    connectioninfo(channel.localip, channel.localport, channel.remoteip, channel.remoteport);

    purge(channel.buf0, sizeof channel.buf0);
    return 1;
}

int channel_openterminal(const char *name, crypto_uint32 a, crypto_uint32 b, crypto_uint32 x, crypto_uint32 y) {
    // Refuse terminal/PTY request
    return 0;
}

void channel_ptyresize(crypto_uint32 a, crypto_uint32 b, crypto_uint32 x, crypto_uint32 y) {
    // No-op
}

int channel_env(const char *x, const char *y) {
    // No-op
    return 1;
}

struct interpreter_args {
    int read_fd;
    int write_fd;
    char *cmd;
};

int channel_exec(const char *cmd) {
    int fds_in[2] = {-1, -1};
    int fds_out[2] = {-1, -1};

    if (channel.maxpacket == 0) bug_proto();
    if (channel.pid != 0) bug_proto();

    if (socketpair_tcp(fds_in) < 0) return 0;
    if (socketpair_tcp(fds_out) < 0) {
        close(fds_in[0]);
        close(fds_in[1]);
        return 0;
    }

    struct interpreter_args *args = malloc(sizeof(struct interpreter_args));
    if (!args) {
        close(fds_in[0]); close(fds_in[1]);
        close(fds_out[0]); close(fds_out[1]);
        return 0;
    }
    args->read_fd = fds_in[1];
    args->write_fd = fds_out[1];
    args->cmd = cmd ? strdup(cmd) : NULL;

    // Spawn the FreeRTOS task running the command interpreter CLI (stack size >= 8 KB)
    BaseType_t ret = xTaskCreate(interpreter_task, "ssh_interpreter", 8192, args, tskIDLE_PRIORITY + 1, NULL);
    if (ret != pdPASS) {
        if (args->cmd) free(args->cmd);
        free(args);
        close(fds_in[0]); close(fds_in[1]);
        close(fds_out[0]); close(fds_out[1]);
        return 0;
    }

    // Set server-side fds
    channel.fd0 = fds_in[0];
    channel.fd1 = fds_out[0];
    channel.fd2 = -1;
    channel.len0 = 0;
    channel.pid = 9999; // Dummy non-zero PID to signify running child process

    return 1;
}

void channel_put(unsigned char *buf, long long len) {
    if (channel.maxpacket == 0) bug_proto();
    if (channel.pid <= 0) bug_proto();
    if (channel.fd0 == -1) bug_proto();

    if (!buf || len < 0) bug_inval();
    if (channel.len0 + len > CHANNEL_BUFSIZE) bug_nomem();

    byte_copy(channel.buf0 + channel.len0, len, buf);
    channel.len0 += len;
    channel.localwindow -= len;
}

void channel_puteof(void) {
    if (channel.maxpacket == 0) bug_proto();
    if (channel.pid == 0) bug_proto();
    if (channel.fd0 == -1) bug_proto();

    channel.remoteeof = 1;
    if (channel.len0 == 0) {
        close(channel.fd0);
        channel.fd0 = -1;
    }
}

int channel_putisready(void) {
    if (channel.maxpacket == 0) return 0;
    if (channel.pid <= 0) return 0;
    if (channel.fd0 == -1) return 0;

    return (CHANNEL_BUFSIZE > channel.len0);
}

long long channel_read(unsigned char *buf, long long len) {
    long long r;

    if (channel.maxpacket == 0) bug_proto();
    if (channel.pid <= 0) bug_proto();
    if (channel.fd1 == -1) bug_proto();

    if (!buf || len < 0) bug_inval();
    if (channel.remotewindow <= 0) return 0;

    r = len;
    if (r > 1048576) r = 1048576;
    if (r > channel.remotewindow) r = channel.remotewindow;
    
    r = read(channel.fd1, buf, r);
    if (r == -1) {
        if (errno == EINTR) return 0;
        if (errno == EAGAIN) return 0;
        if (errno == EWOULDBLOCK) return 0;
    }
    if (r <= 0) {
        close(channel.fd1);
        channel.fd1 = -1;
        return 0;
    }
    channel.remotewindow -= r;
    return r;
}

long long channel_extendedread(unsigned char *buf, long long len) {
    if (channel.fd2 == -1) return 0;
    return 0;
}

int channel_readisready(void) {
    if (channel.maxpacket == 0 || channel.pid == 0) return 0;
    if (channel.fd1 == -1) return 0;
    return (channel.remotewindow > 0);
}

int channel_extendedreadisready(void) {
    return 0;
}

int channel_write(void) {
    long long w;

    if (channel.maxpacket == 0) bug_proto();
    if (channel.pid <= 0) bug_proto();
    if (channel.fd0 == -1) bug_proto();

    if (channel.len0 <= 0) return 1;

    w = write(channel.fd0, channel.buf0, channel.len0);
    if (w == -1) {
        if (errno == EINTR) return 1;
        if (errno == EAGAIN) return 1;
        if (errno == EWOULDBLOCK) return 1;
    }
    if (w <= 0) {
        close(channel.fd0);
        channel.fd0 = -1;
        return 0;
    }
    byte_copy(channel.buf0, channel.len0 - w, channel.buf0 + w);
    purge(channel.buf0 + channel.len0 - w, w);
    channel.len0 -= w;
    if (channel.remoteeof && channel.len0 == 0) {
        close(channel.fd0);
        channel.fd0 = -1;
    }
    return 1;
}

int channel_writeisready(void) {
    if (channel.maxpacket == 0) return 0;
    if (channel.pid <= 0) return 0;
    if (channel.fd0 == -1) return 0;

    return (channel.len0 > 0);
}

int channel_iseof(void) {
    if (channel.maxpacket == 0) return 0;
    if (channel.pid == 0) return 0;
    if (channel.pid == -1) return 1;
    return (channel.fd1 == -1 && channel.fd2 == -1);
}

int channel_waitnohang(int *s, int *e) {
    if (!s || !e) bug_inval();
    if (channel.maxpacket == 0) bug_proto();
    if (channel.pid <= 0) return 0;

    *e = 0;
    *s = 0;
    channel.pid = -1;
    return 1;
}

void channel_purge(void) {
    if (channel.fd0 != -1) { close(channel.fd0); channel.fd0 = -1; }
    if (channel.fd1 != -1) { close(channel.fd1); channel.fd1 = -1; }
    if (channel.fd2 != -1) { close(channel.fd2); channel.fd2 = -1; }
    purge(&channel, sizeof channel);
    trymunlock(&channel, sizeof channel);
}

void channel_init(void) {
    trymlock(&channel, sizeof channel);
    purge(&channel, sizeof channel);
    channel.maxpacket = 0;
    channel.remoteeof = 0;
    channel.len0 = 0;
    channel.pid = 0;
    channel.fd0 = -1;
    channel.fd1 = -1;
    channel.fd2 = -1;
    channel.flagterminal = 0;
    channel.master = -1;
    channel.slave = -1;
}

int channel_getfd0(void) { return channel.fd0; }
int channel_getfd1(void) { return channel.fd1; }
int channel_getfd2(void) { return channel.fd2; }
long long channel_getlen0(void) { return channel.len0; }
crypto_uint32 channel_getid(void) { return channel.id; }
crypto_uint32 channel_getlocalwindow(void) { return channel.localwindow; }
void channel_incrementremotewindow(crypto_uint32 x) { channel.remotewindow += x; }
void channel_incrementlocalwindow(crypto_uint32 x) { channel.localwindow += x; }

// Helper to write string to task socket
static void socket_write_str(int fd, const char *str) {
    send(fd, str, strlen(str), 0);
}

static void interpreter_task(void *pvParameters) {
    struct interpreter_args *args = (struct interpreter_args *)pvParameters;
    int rx_fd = args->read_fd;
    int tx_fd = args->write_fd;
    char *cmd = args->cmd;
    free(args);

    if (cmd) {
        // Run single command and exit
        if (strcmp(cmd, "help") == 0 || strcmp(cmd, "?") == 0) {
            socket_write_str(tx_fd, "Available commands:\r\n");
            socket_write_str(tx_fd, "  help | ?        Show this help message\r\n");
            socket_write_str(tx_fd, "  status          Show ESP32 system status\r\n");
            socket_write_str(tx_fd, "  reboot          Reboot the ESP32 chip\r\n");
            socket_write_str(tx_fd, "  exit            Disconnect the session\r\n");
        } else if (strcmp(cmd, "status") == 0) {
            char status_buf[128];
            esp_chip_info_t chip_info;
            esp_chip_info(&chip_info);

            snprintf(status_buf, sizeof(status_buf), 
                "System Status:\r\n"
                "  Free Heap: %lu bytes\r\n"
                "  Chip Cores: %d\r\n"
                "  IDF Version: %s\r\n",
                (unsigned long)esp_get_free_heap_size(),
                chip_info.cores,
                esp_get_idf_version());
            socket_write_str(tx_fd, status_buf);
        } else if (strcmp(cmd, "reboot") == 0) {
            socket_write_str(tx_fd, "Rebooting ESP32...\r\n");
            vTaskDelay(pdMS_TO_TICKS(500));
            esp_restart();
        } else {
            socket_write_str(tx_fd, "Unknown command. Type 'help' for options.\r\n");
        }
        free(cmd);
        goto cleanup;
    }

    socket_write_str(tx_fd, "\r\n=== Welcome to ESP32 SSH Config Server (TinySSH) ===\r\n");
    socket_write_str(tx_fd, "Type 'help' or '?' for available commands.\r\n");

    char buffer[256];
    int buf_len = 0;

    for (;;) {
        socket_write_str(tx_fd, "\r\nesp32> ");
        buf_len = 0;
        memset(buffer, 0, sizeof(buffer));

        // Read a line from client
        while (buf_len < (int)sizeof(buffer) - 1) {
            char c;
            int r = recv(rx_fd, &c, 1, 0);
            if (r <= 0) {
                // Connection closed or error
                goto cleanup;
            }

            // Echo character back to client
            send(tx_fd, &c, 1, 0);

            if (c == '\r' || c == '\n') {
                break;
            } else if (c == 127 || c == '\b') { // backspace
                if (buf_len > 0) {
                    buf_len--;
                    buffer[buf_len] = '\0';
                    // Echo erase sequence back to client
                    socket_write_str(tx_fd, " \b");
                }
            } else {
                buffer[buf_len++] = c;
            }
        }

        // Trim trailing carriage return / newlines
        while (buf_len > 0 && (buffer[buf_len - 1] == '\r' || buffer[buf_len - 1] == '\n')) {
            buffer[--buf_len] = '\0';
        }

        if (buf_len == 0) {
            continue;
        }

        // Process command
        if (strcmp(buffer, "help") == 0 || strcmp(buffer, "?") == 0) {
            socket_write_str(tx_fd, "\r\nAvailable commands:\r\n");
            socket_write_str(tx_fd, "  help | ?        Show this help message\r\n");
            socket_write_str(tx_fd, "  status          Show ESP32 system status\r\n");
            socket_write_str(tx_fd, "  reboot          Reboot the ESP32 chip\r\n");
            socket_write_str(tx_fd, "  exit            Disconnect the session\r\n");
        } else if (strcmp(buffer, "status") == 0) {
            char status_buf[128];
            esp_chip_info_t chip_info;
            esp_chip_info(&chip_info);

            snprintf(status_buf, sizeof(status_buf), 
                "\r\nSystem Status:\r\n"
                "  Free Heap: %lu bytes\r\n"
                "  Chip Cores: %d\r\n"
                "  IDF Version: %s\r\n",
                (unsigned long)esp_get_free_heap_size(),
                chip_info.cores,
                esp_get_idf_version());
            socket_write_str(tx_fd, status_buf);
        } else if (strcmp(buffer, "reboot") == 0) {
            socket_write_str(tx_fd, "\r\nRebooting ESP32...\r\n");
            vTaskDelay(pdMS_TO_TICKS(500));
            esp_restart();
        } else if (strcmp(buffer, "exit") == 0) {
            socket_write_str(tx_fd, "\r\nGoodbye!\r\n");
            break;
        } else {
            socket_write_str(tx_fd, "\r\nUnknown command. Type 'help' for options.\r\n");
        }
    }

cleanup:
    vTaskDelay(pdMS_TO_TICKS(100));
    close(rx_fd);
    close(tx_fd);
    vTaskDelete(NULL);
}
