#include "global.h"
#include "newenv.h"
#include "channel.h"
#include "packet.h"
#include "sshcrypto.h"
#include "purge.h"
#include "trymlock.h"
#include <stdlib.h>

__thread unsigned char *global_bspace1 = NULL;
__thread unsigned char *global_bspace2 = NULL;

void global_init(void) {
    global_bspace1 = malloc(GLOBAL_BSIZE);
    global_bspace2 = malloc(GLOBAL_BSIZE);
    
    packet_init();
    channel_init();
    newenv_init();
    sshcrypto_init();

    if (global_bspace1) {
        trymlock(global_bspace1, GLOBAL_BSIZE);
        purge(global_bspace1, GLOBAL_BSIZE);
    }
    if (global_bspace2) {
        trymlock(global_bspace2, GLOBAL_BSIZE);
        purge(global_bspace2, GLOBAL_BSIZE);
    }
}

void global_purge(void) {
    unsigned char stack[4096];
    purge(stack, sizeof stack);

    packet_purge();
    channel_purge();
    newenv_purge();
    sshcrypto_purge();

    if (global_bspace1) {
        purge(global_bspace1, GLOBAL_BSIZE);
        trymunlock(global_bspace1, GLOBAL_BSIZE);
        free(global_bspace1);
        global_bspace1 = NULL;
    }
    if (global_bspace2) {
        purge(global_bspace2, GLOBAL_BSIZE);
        trymunlock(global_bspace2, GLOBAL_BSIZE);
        free(global_bspace2);
        global_bspace2 = NULL;
    }
}

void global_die(int x) {
    global_purge();
    _exit(x);
}
