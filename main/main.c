#include <stdio.h>
#include <string.h>
#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_flash.h"
#include "esp_chip_info.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_log.h"

#define TAG "main"

/* ---- Example configuration ----------------------------------------------
 * Replace these placeholders with your own values (or wire them to Kconfig).
 * Do NOT commit real credentials to a public repository.
 */
#define EXAMPLE_STA_SSID       "YOUR_WIFI_SSID"
#define EXAMPLE_STA_PASSWORD   "YOUR_WIFI_PASSWORD"
#define EXAMPLE_AP_SSID        "GloSSH_Config"
#define EXAMPLE_AP_PASSWORD    "changeme1234"   /* WPA2 requires >= 8 chars */
/* Public key authorized for SSH login. Public keys are not secret, but use
 * your own. Generate with: ssh-keygen -t ed25519 */
#define EXAMPLE_AUTHORIZED_KEY "ssh-ed25519 AAAA...replace_me... user@host\n"

static void event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGI(TAG, "Disconnected from Wi-Fi, retrying connection...");
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "Successfully connected! Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
    }
}

static void wifi_init_apsta(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_ap();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    wifi_config_t ap_config = {
        .ap = {
            .ssid = EXAMPLE_AP_SSID,
            .ssid_len = strlen(EXAMPLE_AP_SSID),
            .channel = 1,
            .password = EXAMPLE_AP_PASSWORD,
            .max_connection = 4,
            .authmode = WIFI_AUTH_WPA2_PSK,
        },
    };

    wifi_config_t sta_config = {
        .sta = {
            .ssid = EXAMPLE_STA_SSID,
            .password = EXAMPLE_STA_PASSWORD,
            .threshold.rssi = -127,
            .scan_method = WIFI_FAST_SCAN,
            .sort_method = WIFI_CONNECT_AP_BY_SIGNAL,
        },
    };

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "wifi_init_apsta finished. STA SSID:%s, AP SSID:%s",
             EXAMPLE_STA_SSID, EXAMPLE_AP_SSID);
}

static void provision_authorized_key(void)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open("ssh", NVS_READWRITE, &handle);
    if (err == ESP_OK) {
        const char *auth_key = EXAMPLE_AUTHORIZED_KEY;
        err = nvs_set_str(handle, "authorized_key", auth_key);
        if (err == ESP_OK) {
            nvs_commit(handle);
            ESP_LOGI(TAG, "Successfully provisioned authorized SSH public key in NVS.");
        } else {
            ESP_LOGE(TAG, "Failed to set authorized key in NVS: %d", err);
        }
        nvs_close(handle);
    } else {
        ESP_LOGE(TAG, "Failed to open NVS namespace 'ssh': %d", err);
    }
}

void app_main(void)
{
    printf("Hello world!\n");

    /* Initialize NVS */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* Provision the SSH authorized public key */
    provision_authorized_key();

    /* Print chip information */
    esp_chip_info_t chip_info;
    esp_chip_info(&chip_info);
    printf("This is %s chip with %d CPU cores, WiFi%s%s, ",
            CONFIG_IDF_TARGET,
            chip_info.cores,
            (chip_info.features & CHIP_FEATURE_BT) ? "/BT" : "",
            (chip_info.features & CHIP_FEATURE_BLE) ? "/BLE" : "");

    printf("silicon revision %d, ", chip_info.revision);

    uint32_t flash_size = 0;
    esp_flash_get_size(NULL, &flash_size);
    printf("%dMB %s flash\n", (int)(flash_size / (1024 * 1024)),
            (chip_info.features & CHIP_FEATURE_EMB_FLASH) ? "embedded" : "external");

    printf("Free heap: %d\n", (int)esp_get_free_heap_size());

    /* Initialize WiFi SoftAP + Station */
    wifi_init_apsta();

    extern void ssh_task();
    ssh_task();

    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
