#include "includes.h"
#include "session.h"
#include "auth.h"
#include "dbutil.h"
#include "buffer.h"
#include "runopts.h"
#include "nvs_flash.h"
#include "nvs.h"

#define TAG "dropbear_auth"

static int checkusername(const char *username, unsigned int userlen) {
    if (userlen > MAX_USERNAME_LEN) {
        return DROPBEAR_FAILURE;
    }
    if (strlen(username) != userlen) {
        dropbear_exit("Attempted username with a null byte");
    }
    return DROPBEAR_SUCCESS;
}

void svr_authinitialise(void) {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    ses.authstate.authtypes = 0;
#if DROPBEAR_SVR_PASSWORD_AUTH
    ses.authstate.authtypes |= AUTH_TYPE_PASSWORD;
#endif
#if DROPBEAR_SVR_PUBKEY_AUTH
    ses.authstate.authtypes |= AUTH_TYPE_PUBKEY;
#endif
}

void send_msg_userauth_failure(int partial, int incrfail) {
	buffer *typebuf = NULL;
	TRACE(("enter send_msg_userauth_failure"))

	CHECKCLEARTOWRITE();
	buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_FAILURE);

	typebuf = buf_new(30);
	if (ses.authstate.authtypes & AUTH_TYPE_PUBKEY) {
		buf_putbytes(typebuf, (const unsigned char *)AUTH_METHOD_PUBKEY, AUTH_METHOD_PUBKEY_LEN);
		if (ses.authstate.authtypes & AUTH_TYPE_PASSWORD) {
			buf_putbyte(typebuf, ',');
		}
	}
	if (ses.authstate.authtypes & AUTH_TYPE_PASSWORD) {
		buf_putbytes(typebuf, (const unsigned char *)AUTH_METHOD_PASSWORD, AUTH_METHOD_PASSWORD_LEN);
	}
	buf_putbufstring(ses.writepayload, typebuf);
	buf_free(typebuf);

	buf_putbyte(ses.writepayload, partial ? 1 : 0);
	encrypt_packet();

	if (incrfail) {
		ses.authstate.failcount++;
	}

	if (ses.authstate.failcount >= svr_opts.maxauthtries) {
		dropbear_exit("Max auth tries reached");
	}
	TRACE(("leave send_msg_userauth_failure"))
}

void send_msg_userauth_success() {
	TRACE(("enter send_msg_userauth_success"))
	CHECKCLEARTOWRITE();
	buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_SUCCESS);
	encrypt_packet();

	ses.authstate.authdone = 1;
	ses.connect_time = 0;

	if (ses.authstate.pw_uid == 0) {
		ses.allowprivport = 1;
	}

	if (svr_ses.childpipe >= 0) {
		m_close(svr_ses.childpipe);
		svr_ses.childpipe = -1;
	}
	TRACE(("leave send_msg_userauth_success"))
}

void send_msg_userauth_banner(const buffer *msg) {
	TRACE(("enter send_msg_userauth_banner"))
	CHECKCLEARTOWRITE();
	buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_BANNER);
	buf_putbufstring(ses.writepayload, msg);
	buf_putstring(ses.writepayload, "en", 2);
	encrypt_packet();
	TRACE(("leave send_msg_userauth_banner"))
}

void recv_msg_userauth_request() {
    char *username = NULL, *servicename = NULL, *methodname = NULL;
    unsigned int userlen, servicelen, methodlen;
    int valid_user = 0;

    TRACE(("enter recv_msg_userauth_request"))

    gettime_wrapper(&ses.authstate.auth_starttime);

    if (ses.authstate.authdone == 1) {
        return;
    }

    if (svr_opts.banner) {
        send_msg_userauth_banner(svr_opts.banner);
        buf_free(svr_opts.banner);
        svr_opts.banner = NULL;
    }

    username = buf_getstring(ses.payload, &userlen);
    servicename = buf_getstring(ses.payload, &servicelen);
    methodname = buf_getstring(ses.payload, &methodlen);

    if (servicelen != SSH_SERVICE_CONNECTION_LEN ||
        strncmp(servicename, SSH_SERVICE_CONNECTION, SSH_SERVICE_CONNECTION_LEN) != 0) {
        m_free(username);
        m_free(servicename);
        m_free(methodname);
        dropbear_exit("unknown service in auth");
    }

    if (checkusername(username, userlen) == DROPBEAR_SUCCESS) {
        valid_user = 1;
    }

    if (methodlen == AUTH_METHOD_NONE_LEN &&
        strncmp(methodname, AUTH_METHOD_NONE, AUTH_METHOD_NONE_LEN) == 0) {
        send_msg_userauth_failure(0, 0);
        goto out;
    }

#if DROPBEAR_SVR_PASSWORD_AUTH
    if (methodlen == AUTH_METHOD_PASSWORD_LEN &&
        strncmp(methodname, AUTH_METHOD_PASSWORD, AUTH_METHOD_PASSWORD_LEN) == 0) {
        
        unsigned int changepw = buf_getbool(ses.payload);
        if (changepw) {
            send_msg_userauth_failure(0, 1);
            goto out;
        }

        unsigned int passwordlen;
        char *password = buf_getstring(ses.payload, &passwordlen);
        
        int auth_success = 0;
        nvs_handle_t my_handle;
        if (nvs_open("ssh", NVS_READONLY, &my_handle) == ESP_OK) {
            char stored_passwd[64];
            size_t required_size = sizeof(stored_passwd);
            if (nvs_get_str(my_handle, "password", stored_passwd, &required_size) == ESP_OK) {
                if (passwordlen == strlen(stored_passwd) &&
                    constant_time_memcmp(password, stored_passwd, passwordlen) == 0) {
                    auth_success = 1;
                }
            } else {
                if (passwordlen == 5 && memcmp(password, "esp32", 5) == 0) {
                    auth_success = 1;
                }
            }
            nvs_close(my_handle);
        } else {
            if (passwordlen == 5 && memcmp(password, "esp32", 5) == 0) {
                auth_success = 1;
            }
        }

        m_burn(password, passwordlen);
        m_free(password);

        if (valid_user && auth_success) {
            if (ses.authstate.username) m_free(ses.authstate.username);
            ses.authstate.username = m_strdup(username);
            ses.authstate.pw_uid = 0;
            ses.authstate.pw_gid = 0;
            ses.authstate.pw_dir = m_strdup("/");
            ses.authstate.pw_shell = m_strdup("/bin/sh");
            ses.authstate.pw_name = m_strdup(username);

            dropbear_log(LOG_NOTICE, "Password auth succeeded for '%s'", username);
            send_msg_userauth_success();
        } else {
            dropbear_log(LOG_WARNING, "Bad password attempt for '%s'", username);
            send_msg_userauth_failure(0, 1);
        }
        goto out;
    }
#endif

    send_msg_userauth_failure(0, 1);

out:
    m_free(username);
    m_free(servicename);
    m_free(methodname);
}
