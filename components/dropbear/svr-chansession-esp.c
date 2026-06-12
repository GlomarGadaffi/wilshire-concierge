#include "includes.h"
#include "session.h"
#include "chansession.h"
#include "dbutil.h"
#include "channel.h"

static int newchansess(struct Channel *UNUSED(channel)) {
    return 0;
}

static int sesscheckclose(const struct Channel *UNUSED(channel)) {
    return 1;
}

static void chansessionrequest(struct Channel *UNUSED(channel)) {
}

static void closechansess(struct Channel *UNUSED(channel)) {
}

static void cleanupchansess(struct Channel *UNUSED(channel)) {
}

const struct ChanType svrchansess = {
	0, /* sepfds */
	"session", /* name */
	newchansess, /* inithandler */
	sesscheckclose, /* checkclosehandler */
	chansessionrequest, /* reqhandler */
	closechansess, /* closehandler */
	cleanupchansess /* cleanup */
};

void svr_chansessinitialise(void) {
}

void svr_chansess_checksignal(void) {
}
