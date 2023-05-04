/*
 * "Adb" backend.
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include "putty.h"

#define ADB_MAX_BACKLOG 4096

typedef struct Adb Adb;
struct Adb {
    Socket *s;
    bool closed_on_socket_error;
    size_t bufsize;
    Seat *seat;
    LogContext *logctx;
    Ldisc *ldisc;
    bool sent_console_eof, sent_socket_eof, socket_connected;
    char *description;

    Conf *conf;

    Plug plug;
    Backend backend;
    Interactor interactor;
	int state;
};

static void adb_size(Backend *be, int width, int height);

static void c_write(Adb *adb, const void *buf, size_t len)
{
    size_t backlog = seat_stdout(adb->seat, buf, len);
    sk_set_frozen(adb->s, backlog > ADB_MAX_BACKLOG);
}

static void adb_log(Plug *plug, PlugLogType type, SockAddr *addr, int port,
                    const char *error_msg, int error_code)
{
    Adb *adb = container_of(plug, Adb, plug);
    backend_socket_log(adb->seat, adb->logctx, type, addr, port, error_msg,
                       error_code, adb->conf, adb->socket_connected);
    if (type == PLUGLOG_CONNECT_SUCCESS) {
        adb->socket_connected = true;
        if (adb->ldisc)
            ldisc_check_sendok(adb->ldisc);
    }
}

static void adb_check_close(Adb *adb)
{
    /*
     * Called after we send EOF on either the socket or the console.
     * Its job is to wind up the session once we have sent EOF on both.
     */
    if (adb->sent_console_eof && adb->sent_socket_eof) {
        if (adb->s) {
            sk_close(adb->s);
            adb->s = NULL;
            seat_notify_remote_exit(adb->seat);
            seat_notify_remote_disconnect(adb->seat);
        }
    }
}

static void adb_closing(Plug *plug, PlugCloseType type, const char *error_msg)
{
    Adb *adb = container_of(plug, Adb, plug);

    if (type != PLUGCLOSE_NORMAL) {
        /* A socket error has occurred. */
        if (adb->s) {
            sk_close(adb->s);
            adb->s = NULL;
            adb->closed_on_socket_error = true;
            seat_notify_remote_exit(adb->seat);
            seat_notify_remote_disconnect(adb->seat);
        }
        logevent(adb->logctx, error_msg);
        if (type != PLUGCLOSE_USER_ABORT)
            seat_connection_fatal(adb->seat, "%s", error_msg);
    } else {
        /* Otherwise, the remote side closed the connection normally. */
        if (!adb->sent_console_eof && seat_eof(adb->seat)) {
            /*
             * The front end wants us to close the outgoing side of the
             * connection as soon as we see EOF from the far end.
             */
            if (!adb->sent_socket_eof) {
                if (adb->s)
                    sk_write_eof(adb->s);
                adb->sent_socket_eof= true;
            }
        }
        adb->sent_console_eof = true;
        adb_check_close(adb);
    }
}

static void adb_receive(Plug *plug, int urgent, const char *data, size_t len)
{
    Adb *adb = container_of(plug, Adb, plug);
	if (adb->state==1) {
		if (data[0]=='O') { // OKAY
			sk_write(adb->s,"0006shell:",10);
			adb->state=2; // wait for shell start response
		} else {
			if (data[0]=='F') {
				char* d = (char*)smalloc(len+1);
				memcpy(d,data,len);
				d[len]='\0';
				seat_connection_fatal(adb->seat, "%s", d+8);
				sfree(d);
			} else {
				seat_connection_fatal(adb->seat, "Bad response");
			}
			return;
		}
	} else if (adb->state==2) {
		if (data[0]=='O') { //OKAY
			adb->state=3; // shell started, switch to terminal mode
		} else {
			if (data[0]=='F') {
				char* d = (char*)smalloc(len+1);
				memcpy(d,data,len);
				d[len]='\0';
				seat_connection_fatal(adb->seat, "%s", d+8);
				sfree(d);
			} else {
				seat_connection_fatal(adb->seat, "Bad response");
			}
			return;
		}
	} else {
		c_write(adb, data, len);
	}
}

static void adb_sent(Plug *plug, size_t bufsize)
{
    Adb *adb = container_of(plug, Adb, plug);
    adb->bufsize = bufsize;
    seat_sent(adb->seat, adb->bufsize);
}

static const PlugVtable Adb_plugvt = {
    .log = adb_log,
    .closing = adb_closing,
    .receive = adb_receive,
    .sent = adb_sent,
};

static char *adb_description(Interactor *itr)
{
    Adb *adb = container_of(itr, Adb, interactor);
    return dupstr(adb->description);
}

static LogPolicy *adb_logpolicy(Interactor *itr)
{
    Adb *adb = container_of(itr, Adb, interactor);
    return log_get_policy(adb->logctx);
}

static Seat *adb_get_seat(Interactor *itr)
{
    Adb *adb = container_of(itr, Adb, interactor);
    return adb->seat;
}

static void adb_set_seat(Interactor *itr, Seat *seat)
{
    Adb *adb = container_of(itr, Adb, interactor);
    adb->seat = seat;
}

static const InteractorVtable Adb_interactorvt = {
    .description = adb_description,
    .logpolicy = adb_logpolicy,
    .get_seat = adb_get_seat,
    .set_seat = adb_set_seat,
};

/*
 * Called to set up the adb connection.
 *
 * Returns an error message, or NULL on success.
 *
 * Also places the canonical host name into `realhost'. It must be
 * freed by the caller.
 */
static char *adb_init(const BackendVtable *vt, Seat *seat,
                      Backend **backend_handle, LogContext *logctx,
                      Conf *conf, const char *host, int port,
                      char **realhost, bool nodelay, bool keepalive)
{
    SockAddr *addr;
    const char *err;
    Adb *adb;
    int addressfamily;
    char *loghost;
	char sendhost[512];

    adb = snew(Adb);
    memset(adb, 0, sizeof(Adb));
    adb->plug.vt = &Adb_plugvt;
    adb->backend.vt = vt;
    adb->interactor.vt = &Adb_interactorvt;
    adb->backend.interactor = &adb->interactor;
    adb->s = NULL;
	adb->state = 0;
    adb->closed_on_socket_error = false;
    *backend_handle = &adb->backend;
    adb->sent_console_eof = adb->sent_socket_eof = false;
    adb->bufsize = 0;
    adb->socket_connected = false;
    adb->conf = conf_copy(conf);
    adb->description = default_description(vt, host, port);

    adb->seat = seat;
    adb->logctx = logctx;

    addressfamily = conf_get_int(conf, CONF_addressfamily);
    /*
     * Try to find host.
     */
    addr = name_lookup("localhost", port, realhost, conf, addressfamily,
                       adb->logctx, "main connection");
    if ((err = sk_addr_error(addr)) != NULL) {
        sk_addr_free(addr);
        return dupstr(err);
    }

    if (port < 0)
        port = 5037;                     /* default adb port */

    /*
     * Open socket.
     */
    adb->s = new_connection(addr, *realhost, port, false, true, nodelay,
                            keepalive, &adb->plug, conf, &adb->interactor);
    if ((err = sk_socket_error(adb->s)) != NULL)
        return dupstr(err);

    /* No local authentication phase in this protocol */
    seat_set_trust_status(adb->seat, false);

    loghost = conf_get_str(conf, CONF_loghost);
    if (*loghost) {
        char *colon;

        sfree(*realhost);
        *realhost = dupstr(loghost);

        colon = host_strrchr(*realhost, ':');
        if (colon)
            *colon++ = '\0';
    }

	/* send initial data to adb server */

	snprintf(sendhost,512,"%04xhost:%s",strlen(host)+5,host);

	sk_write(adb->s,sendhost,strlen(host)+9);

	adb->state = 1;
    return NULL;
}

static void adb_free(Backend *be)
{
    Adb *adb = container_of(be, Adb, backend);

    if (is_tempseat(adb->seat))
        tempseat_free(adb->seat);
    if (adb->s)
        sk_close(adb->s);
    conf_free(adb->conf);
    sfree(adb->description);
    sfree(adb);
}

/*
 * Stub routine (we don't have any need to reconfigure this backend).
 */
static void adb_reconfig(Backend *be, Conf *conf)
{
}

/*
 * Called to send data down the adb connection.
 */
static void adb_send(Backend *be, const char *buf, size_t len)
{
    Adb *adb = container_of(be, Adb, backend);

    if (adb->s == NULL)
        return;

    adb->bufsize = sk_write(adb->s, buf, len);
}

/*
 * Called to query the current socket sendability status.
 */
static size_t adb_sendbuffer(Backend *be)
{
    Adb *adb = container_of(be, Adb, backend);
    return adb->bufsize;
}

/*
 * Called to set the size of the window
 */
static void adb_size(Backend *be, int width, int height)
{
    /* Do nothing! */
    return;
}

/*
 * Send adb special codes. We only handle outgoing EOF here.
 */
static void adb_special(Backend *be, SessionSpecialCode code, int arg)
{
    Adb *adb = container_of(be, Adb, backend);
    if (code == SS_EOF && adb->s) {
        sk_write_eof(adb->s);
        adb->sent_socket_eof= true;
        adb_check_close(adb);
    }

    return;
}

/*
 * Return a list of the special codes that make sense in this
 * protocol.
 */
static const SessionSpecial *adb_get_specials(Backend *be)
{
    return NULL;
}

static bool adb_connected(Backend *be)
{
    Adb *adb = container_of(be, Adb, backend);
    return adb->s != NULL;
}

static bool adb_sendok(Backend *be)
{
    Adb *adb = container_of(be, Adb, backend);
    return adb->socket_connected;
}

static void adb_unthrottle(Backend *be, size_t backlog)
{
    Adb *adb = container_of(be, Adb, backend);
    sk_set_frozen(adb->s, backlog > ADB_MAX_BACKLOG);
}

static bool adb_ldisc(Backend *be, int option)
{
    // Don't allow line discipline options

    return false;
}

static void adb_provide_ldisc(Backend *be, Ldisc *ldisc)
{
    Adb *adb = container_of(be, Adb, backend);
    adb->ldisc = ldisc;
}

static int adb_exitcode(Backend *be)
{
    Adb *adb = container_of(be, Adb, backend);
    if (adb->s != NULL)
        return -1;                     /* still connected */
    else if (adb->closed_on_socket_error)
        return INT_MAX;     /* a socket error counts as an unclean exit */
    else
        /* Exit codes are a meaningless concept in the Adb protocol */
        return 0;
}

/*
 * cfg_info for Adb does nothing at all.
 */
static int adb_cfg_info(Backend *be)
{
    return 0;
}

const BackendVtable adb_backend = {
    .init = adb_init,
    .free = adb_free,
    .reconfig = adb_reconfig,
    .send = adb_send,
    .sendbuffer = adb_sendbuffer,
    .size = adb_size,
    .special = adb_special,
    .get_specials = adb_get_specials,
    .connected = adb_connected,
    .exitcode = adb_exitcode,
    .sendok = adb_sendok,
    .ldisc_option_state = adb_ldisc,
    .provide_ldisc = adb_provide_ldisc,
    .unthrottle = adb_unthrottle,
    .cfg_info = adb_cfg_info,
    .id = "adb",
    .displayname_tc = "Adb",
    .displayname_lc = "adb",
    .protocol = PROT_ADB,
    .default_port = 5037,
};
