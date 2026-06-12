#ifndef _TERMIOS_MOCK_H_
#define _TERMIOS_MOCK_H_

#include <string.h>

#define NCCS 32
typedef unsigned char cc_t;
typedef unsigned int speed_t;
typedef unsigned int tcflag_t;

struct termios {
	tcflag_t      c_iflag;
	tcflag_t      c_oflag;
	tcflag_t      c_cflag;
	tcflag_t      c_lflag;
	cc_t          c_cc[NCCS];
	speed_t       c_ispeed;
	speed_t       c_ospeed;
};

#define TCSANOW         0
#define TCSADRAIN       1
#define TCSAFLUSH       2

#define ECHO            0x00000008

#define VINTR 0
#define VQUIT 1
#define VERASE 2
#define VKILL 3
#define VEOF 4
#define VEOL 5
#define VEOL2 6
#define VSTART 7
#define VSTOP 8
#define VSUSP 9
#define VREPRINT 10
#define VWERASE 11
#define VLNEXT 12
#define VDISCARD 13

#define IGNPAR 0x0001
#define PARMRK 0x0002
#define INPCK  0x0004
#define ISTRIP 0x0008
#define INLCR  0x0010
#define IGNCR  0x0020
#define ICRNL  0x0040
#define IXON   0x0080
#define IXANY  0x0100
#define IXOFF  0x0200

#define ISIG   0x0001
#define ICANON 0x0002
#define ECHOE  0x0010
#define ECHOK  0x0020
#define ECHONL 0x0040
#define NOFLSH 0x0080
#define TOSTOP 0x0100
#define IEXTEN 0x0200

#define OPOST  0x0001
#define ONLCR  0x0002

#define CS7    0x0020
#define CS8    0x0030
#define PARENB 0x0100
#define PARODD 0x0200

static inline int tcgetattr(int fd, struct termios *t) {
	if (t) {
		memset(t, 0, sizeof(*t));
	}
	return 0;
}

static inline int tcsetattr(int fd, int actions, const struct termios *t) {
	return 0;
}

#endif
