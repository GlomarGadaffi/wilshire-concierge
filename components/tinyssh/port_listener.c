#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <setjmp.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

#define TAG "port_listener"

// Define the thread-local jmp_buf pointer
__thread jmp_buf *tinyssh_jmp_env = NULL;

extern __thread int tinyssh_conn_fd;

// Forward declaration of main_tinysshd
extern int main_tinysshd(int argc, char **argv);

// Session task
static void ssh_session_task(void *pvParameters) {
    int client_fd = (int)pvParameters;
    
    // Set thread-local socket fd
    tinyssh_conn_fd = client_fd;

    // Set up setjmp env for safe _exit recovery
    jmp_buf env;
    tinyssh_jmp_env = &env;

    ESP_LOGI(TAG, "Starting SSH session for fd %d", client_fd);

    if (setjmp(env) == 0) {
        // Run tinysshd main loop. Pass dummy arguments.
        // tinysshd expects: argv[1] = keydir
        char *dummy_argv[] = { "tinysshd", "/dummy_nvs_keys", NULL };
        main_tinysshd(2, dummy_argv);
    } else {
        ESP_LOGI(TAG, "SSH session for fd %d exited cleanly via longjmp.", client_fd);
    }

    // Session ended, clean up
    close(client_fd);
    tinyssh_jmp_env = NULL;
    vTaskDelete(NULL);
}

// Listener task
static void ssh_listener_task(void *pvParameters) {
    int port = (int)pvParameters;
    int listen_fd = -1;
    struct sockaddr_in serv_addr;

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        ESP_LOGE(TAG, "Failed to create listening socket.");
        vTaskDelete(NULL);
        return;
    }

    int reuse = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(port);

    if (bind(listen_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        ESP_LOGE(TAG, "Failed to bind to port %d.", port);
        close(listen_fd);
        vTaskDelete(NULL);
        return;
    }

    if (listen(listen_fd, 5) < 0) {
        ESP_LOGE(TAG, "Failed to listen on port %d.", port);
        close(listen_fd);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "SSH server listening on port %d...", port);

    for (;;) {
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int client_fd = accept(listen_fd, (struct sockaddr *)&cli_addr, &cli_len);
        if (client_fd < 0) {
            ESP_LOGW(TAG, "Failed to accept connection.");
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        ESP_LOGI(TAG, "Accepted connection, spawning session task.");
        // Spawn a session task (stack size 12 KB to accommodate tinyssh stack requirements)
        BaseType_t ret = xTaskCreate(ssh_session_task, "ssh_session", 12288, (void*)client_fd, tskIDLE_PRIORITY + 5, NULL);
        if (ret != pdPASS) {
            ESP_LOGE(TAG, "Failed to spawn session task.");
            close(client_fd);
        }
    }

    close(listen_fd);
    vTaskDelete(NULL);
}

esp_err_t start_ssh_server(int port) {
    BaseType_t ret = xTaskCreate(ssh_listener_task, "ssh_listener", 4096, (void*)port, tskIDLE_PRIORITY + 4, NULL);
    return (ret == pdPASS) ? ESP_OK : ESP_FAIL;
}

void ssh_task(void) {
    start_ssh_server(22);
}
