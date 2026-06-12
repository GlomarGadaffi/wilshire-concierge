#include "randombytes.h"
#include "esp_random.h"

// Define the thread-local connection file descriptor
__thread int tinyssh_conn_fd = -1;

void randombytes(unsigned char *x, unsigned long long xlen) {
    // esp_fill_random is the hardware RNG cryptographically secure source in ESP-IDF
    esp_fill_random(x, xlen);
}
