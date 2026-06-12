
#define NON_INETD_MODE 1
#define INETD_MODE 0

/* Enable TCP Fowarding */
/* 'Local' is "-L" style (client listening port forwarded via server)
 * 'Remote' is "-R" style (server listening port forwarded via client) */
#define DROPBEAR_CLI_LOCALTCPFWD 0
#define DROPBEAR_CLI_REMOTETCPFWD 0

#define DROPBEAR_SVR_LOCALTCPFWD 0
#define DROPBEAR_SVR_REMOTETCPFWD 0

/* Enable Authentication Agent Forwarding */
#define DROPBEAR_SVR_AGENTFWD 0
#define DROPBEAR_CLI_AGENTFWD 0


/* Note: Both DROPBEAR_CLI_PROXYCMD and DROPBEAR_CLI_NETCAT must be set to
 * allow multihop dbclient connections */

/* Allow using -J <proxycommand> to run the connection through a 
   pipe to a program, rather the normal TCP connection */
#define DROPBEAR_CLI_PROXYCMD 0

/* Enable "Netcat mode" option. This will forward standard input/output
 * to a remote TCP-forwarded connection */
#define DROPBEAR_CLI_NETCAT 0

/* Whether to support "-c" and "-m" flags to choose ciphers/MACs at runtime */
#define DROPBEAR_USER_ALGO_LIST 0

/* Whether to print the message of the day (MOTD). */
#define DO_MOTD 0
#define MOTD_FILENAME "/etc/motd"

/* if you want to enable running an sftp server (such as the one included with
 * OpenSSH), set the path below and set DROPBEAR_SFTPSERVER. 
 * The sftp-server program is not provided by Dropbear itself */
#define DROPBEAR_SFTPSERVER 0
#define SFTPSERVER_PATH "/usr/libexec/sftp-server"

/* Window size limits. These tend to be a trade-off between memory
   usage and network performance: */
/* Size of the network receive window. This amount of memory is allocated
   as a per-channel receive buffer. Increasing this value can make a
   significant difference to network performance. 24kB was empirically
   chosen for a 100mbit ethernet network. The value can be altered at
   runtime with the -W argument. */
#define DEFAULT_RECV_WINDOW 8096

/* Maximum size of a transmitted data packet - this can be any value,
   though increasing it may not make a significant difference. */
#define TRANS_MAX_PAYLOAD_LEN 8096

#define DROPBEAR_SVR_PASSWORD_AUTH 1
#define DROPBEAR_SVR_PAM_AUTH 0

/* ~/.ssh/authorized_keys authentication */
#define DROPBEAR_SVR_PUBKEY_AUTH 0


#define DROPBEAR_USE_PASSWORD_ENV 0
#define MAX_UNAUTH_PER_IP 1
#define MAX_UNAUTH_CLIENTS 3

#define DROPBEAR_SIGNKEY_VERIFY 1
