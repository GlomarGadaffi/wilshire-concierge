#ifndef _TINYSSH_CONFIG_H_
#define _TINYSSH_CONFIG_H_

#define HASASMVOLATILEMEMORY 1
#define HASLIMITS 1

#include <unistd.h>
#include <sys/socket.h>
#include <poll.h>

// Thread-local socket storage for redirecting connection I/O
extern __thread int tinyssh_conn_fd;

static inline ssize_t tinyssh_read(int fd, void *buf, size_t count) {
    if (fd == 0) {
        return recv(tinyssh_conn_fd, buf, count, 0);
    }
    return read(fd, buf, count);
}

static inline ssize_t tinyssh_write(int fd, const void *buf, size_t count) {
    if (fd == 1) {
        return send(tinyssh_conn_fd, buf, count, 0);
    }
    return write(fd, buf, count);
}

static inline int tinyssh_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    for (nfds_t i = 0; i < nfds; ++i) {
        if (fds[i].fd == 0 || fds[i].fd == 1) {
            fds[i].fd = tinyssh_conn_fd;
        }
    }
    return poll(fds, nfds, timeout);
}

#define read(fd, buf, count) tinyssh_read(fd, buf, count)
#define write(fd, buf, count) tinyssh_write(fd, buf, count)
#define poll(fds, nfds, timeout) tinyssh_poll(fds, nfds, timeout)

static inline unsigned int tinyssh_alarm(unsigned int seconds) { return 0; }
static inline void (*tinyssh_signal(int signum, void (*handler)(int)))(int) { return NULL; }

#define chdir(path) (0)
#define fchdir(fd) (0)
#define alarm tinyssh_alarm
#define signal tinyssh_signal

#include <setjmp.h>
extern __thread jmp_buf *tinyssh_jmp_env;
static inline void tinyssh_task_exit(int status) __attribute__((noreturn));
static inline void tinyssh_task_exit(int status) {
    if (tinyssh_jmp_env) {
        longjmp(*tinyssh_jmp_env, 1);
    }
    for (;;) {
        // Fallback loop
    }
}
#define _exit(status) tinyssh_task_exit(status)


// -------------------------------------------------------------
// global.h Override (Downsized Buffer System)
// -------------------------------------------------------------
#define _GLOBAL_H____
#define GLOBAL_BSIZE 8192

extern __thread unsigned char *global_bspace1;
extern __thread unsigned char *global_bspace2;

extern void global_init(void);
extern void global_purge(void);
extern void global_die(int);


// -------------------------------------------------------------
// packet.h Override (Downsized Buffer System)
// -------------------------------------------------------------
#define _PACKET_H____

#define PACKET_UNAUTHENTICATED_MESSAGES 30
#define PACKET_LIMIT 4096
#define PACKET_FULLLIMIT 4300
#define PACKET_RECVLIMIT 16384
#define PACKET_ZEROBYTES 64

// Include buf.h, limit.h, sshcrypto.h and channel.h for types used in struct packet
#include "buf.h"
#include "limit.h"
#include "sshcrypto.h"
#include "channel.h"

struct tinyssh_packet {
    /* flags */
    int flagkeys;
    int flagauthorized;
    int flagrekeying;

    /* channel */
    int flageofsent;
    int flagclosesent;
    int flagchanneleofreceived;

    /* packet id */
    unsigned int sendpacketid;
    unsigned int receivepacketid;

    /* keys */
    unsigned char serverkey[sshcrypto_cipher_KEYMAX];
    unsigned char clientkey[sshcrypto_cipher_KEYMAX];
    unsigned char servermackey[sshcrypto_cipher_KEYMAX];
    unsigned char clientmackey[sshcrypto_cipher_KEYMAX];
    unsigned char servernonce[sshcrypto_cipher_KEYMAX];
    unsigned char clientnonce[sshcrypto_cipher_KEYMAX];
    unsigned char sessionid[sshcrypto_hash_MAX];
    char name[LOGIN_NAME_MAX + 1];
    unsigned char kex_packet_follows;
    unsigned char kex_guess;

    /* buffers */
    unsigned char hellosendspace[256];
    unsigned char helloreceivespace[256];
    unsigned char kexsendspace[1024];
    unsigned char kexrecvspace[8192];
    unsigned char hashbufspace[8192];
    struct buf hellosend;
    struct buf helloreceive;
    struct buf kexsend;
    struct buf kexrecv;
    struct buf hashbuf;

    /* send/recv */
    unsigned char recvbufspace[4 * PACKET_FULLLIMIT + 1 + PACKET_ZEROBYTES];
    unsigned char sendbufspace[4 * PACKET_FULLLIMIT + 1];
    struct buf recvbuf;
    struct buf sendbuf;
    unsigned int packet_length;
};

extern __thread struct tinyssh_packet *packet_ptr;
#define packet (*packet_ptr)

// Function prototypes from packet.h
extern void packet_purge(void);
extern void packet_init(void);

extern int packet_sendisready(void);
extern int packet_send(void);
extern int packet_sendall(void);

extern int packet_recvisready(void);
extern int packet_recv(void);

extern int packet_get(struct buf *, unsigned char);
extern int packet_getall(struct buf *, unsigned char);

extern void packet_put(struct buf *);
extern int packet_putisready(void);

extern int packet_hello_send(void);
extern int packet_hello_receive(void);

extern int packet_kex_send(void);
extern int packet_kex_receive(void);

extern int packet_kexdh(const char *, struct buf *, struct buf *);

extern int packet_auth(struct buf *, struct buf *);

extern int packet_channel_open(struct buf *, struct buf *);
extern int packet_channel_request(struct buf *, struct buf *);

extern int packet_channel_recv_data(struct buf *);
extern int packet_channel_recv_extendeddata(struct buf *);
extern int packet_channel_recv_windowadjust(struct buf *);
extern int packet_channel_recv_eof(struct buf *);
extern int packet_channel_recv_close(struct buf *);

extern void packet_channel_send_data(struct buf *);
extern void packet_channel_send_extendeddata(struct buf *);
extern int packet_channel_send_windowadjust(struct buf *);
extern void packet_channel_send_eof(struct buf *);
extern int packet_channel_send_close(struct buf *, int, int);

extern int packet_unimplemented(struct buf *);

#endif // _TINYSSH_CONFIG_H_
