#include <string.h>
#include "load.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "crypto_sign_ed25519.h"
#include "log.h"

static int init_nvs(void) {
    static int initialized = 0;
    if (initialized) return 0;
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        err = nvs_flash_init();
    }
    if (err == ESP_OK) {
        initialized = 1;
        return 0;
    }
    return -1;
}

int load(const char *fn, void *x, long long xlen) {
    if (init_nvs() != 0) {
        return -1;
    }

    nvs_handle_t handle;
    esp_err_t err = nvs_open("ssh", NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        return -1;
    }

    const char *nvs_key = NULL;
    if (strcmp(fn, "ed25519.pk") == 0) {
        nvs_key = "ed25519_pk";
    } else if (strcmp(fn, ".ed25519.sk") == 0) {
        nvs_key = "ed25519_sk";
    } else {
        nvs_close(handle);
        return -1; // Unknown file
    }

    size_t size = xlen;
    err = nvs_get_blob(handle, nvs_key, x, &size);
    
    // If not found, let's generate a key pair and store both in NVS!
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        unsigned char pk[32];
        unsigned char sk[64];
        
        log_d1("SSH host keys not found in NVS. Generating new Ed25519 key pair...");
        if (crypto_sign_ed25519_keypair(pk, sk) != 0) {
            nvs_close(handle);
            return -1;
        }

        esp_err_t err_pk = nvs_set_blob(handle, "ed25519_pk", pk, sizeof(pk));
        esp_err_t err_sk = nvs_set_blob(handle, "ed25519_sk", sk, sizeof(sk));
        if (err_pk == ESP_OK && err_sk == ESP_OK) {
            nvs_commit(handle);
        } else {
            log_w1("Failed to write generated SSH keys to NVS!");
        }

        if (strcmp(nvs_key, "ed25519_pk") == 0) {
            memcpy(x, pk, (size_t)xlen < sizeof(pk) ? (size_t)xlen : sizeof(pk));
        } else {
            memcpy(x, sk, (size_t)xlen < sizeof(sk) ? (size_t)xlen : sizeof(sk));
        }
        err = ESP_OK;
    }

    nvs_close(handle);
    return (err == ESP_OK) ? xlen : -1;
}

int open_cwd(void) {
    return 999; // Dummy fd indicating success
}

int open_pipe(int *fd) {
    return -1;
}

int open_read(const char *fn) {
    return -1;
}

int open_write(const char *fn) {
    return -1;
}
