#include <string.h>
#include "subprocess.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "log.h"
#include "str.h"

static int findnameandkey(const char *keyname, const char *key, char *x) {
    if (!str_start(x, keyname)) return 0;
    x += str_len(keyname);
    if (*x != ' ') return 0;
    x += 1;
    if (!str_start(x, key)) return 0;
    x += str_len(key);
    if (*x == ' ') return 1;
    if (*x == '\n') return 1;
    if (*x == '\r') return 1;
    if (*x == 0) return 1;
    return 0;
}

int subprocess_auth(const char *account, const char *keyname, const char *key) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open("ssh", NVS_READONLY, &handle);
    if (err != ESP_OK) {
        log_w1("auth: unable to open NVS namespace 'ssh'");
        return -1;
    }

    char line[512];
    size_t size = sizeof(line) - 1;
    memset(line, 0, sizeof(line));
    err = nvs_get_str(handle, "authorized_key", line, &size);
    nvs_close(handle);

    if (err == ESP_OK) {
        if (findnameandkey(keyname, key, line)) {
            log_i2("auth: public key authorized successfully for account ", account);
            return 0; // Success
        }
    } else if (err == ESP_ERR_NVS_NOT_FOUND) {
        log_w1("auth: 'authorized_key' not found in NVS!");
    }

    log_w1("auth: public key authorization failed");
    return 111; // Failure
}
