#include "includes.h"
#include "session.h"
#include "crypto_desc.h"

void ssh_task()
{
    crypto_init();
    //load_all_hostkeys();
    svr_session(0, -1);
}
