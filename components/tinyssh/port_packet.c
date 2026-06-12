#include "packet.h"
#include "purge.h"
#include "trymlock.h"
#include <stdlib.h>

__thread struct tinyssh_packet *packet_ptr = NULL;

void packet_purge(void) {
    if (packet_ptr) {
        purge(packet_ptr, sizeof(struct tinyssh_packet));
        trymunlock(packet_ptr, sizeof(struct tinyssh_packet));
        free(packet_ptr);
        packet_ptr = NULL;
    }
}

void packet_init(void) {
    packet_ptr = malloc(sizeof(struct tinyssh_packet));
    if (!packet_ptr) {
        return;
    }
    trymlock(packet_ptr, sizeof(struct tinyssh_packet));
    purge(packet_ptr, sizeof(struct tinyssh_packet));

    packet_ptr->flagkeys = 0;
    packet_ptr->flagauthorized = 0;
    packet_ptr->flagrekeying = 0;
    packet_ptr->flageofsent = 0;
    packet_ptr->flagclosesent = 0;
    packet_ptr->flagchanneleofreceived = 0;
    packet_ptr->sendpacketid = 0;
    packet_ptr->receivepacketid = 0;
    packet_ptr->packet_length = 0;

    buf_init(&packet_ptr->hellosend, packet_ptr->hellosendspace, sizeof packet_ptr->hellosendspace);
    buf_init(&packet_ptr->helloreceive, packet_ptr->helloreceivespace, sizeof packet_ptr->helloreceivespace);
    buf_init(&packet_ptr->kexsend, packet_ptr->kexsendspace, sizeof packet_ptr->kexsendspace);
    buf_init(&packet_ptr->kexrecv, packet_ptr->kexrecvspace, sizeof packet_ptr->kexrecvspace);
    buf_init(&packet_ptr->hashbuf, packet_ptr->hashbufspace, sizeof packet_ptr->hashbufspace);
    buf_init(&packet_ptr->sendbuf, packet_ptr->sendbufspace, sizeof packet_ptr->sendbufspace);
    buf_init(&packet_ptr->recvbuf, packet_ptr->recvbufspace, sizeof packet_ptr->recvbufspace);
}
