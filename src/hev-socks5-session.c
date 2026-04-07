/*
 ============================================================================
 Name        : hev-socks5-session.c
 Author      : hev <r@hev.cc>
 Copyright   : Copyright (c) 2017 - 2023 hev
 Description : Socks5 Session
 ============================================================================
 */

#include <string.h>
#include <unistd.h>
#include <sys/un.h>

#include <hev-task.h>
#include <hev-task-io-socket.h>

#include "hev-socks5.h"
#include "hev-socks5-misc.h"

#include "hev-logger.h"
#include "hev-config.h"
#include "hev-socks5-client.h"

#include "hev-socks5-session.h"

static int
hev_socks5_session_connect_unix (HevSocks5Session *self, const char *path)
{
    HevSocks5Class *klass;
    struct sockaddr_un addr = { 0 };
    size_t path_len;
    int fd;
    int res;

    path_len = strlen (path);
    if (!path_len || path_len >= sizeof (addr.sun_path)) {
        LOG_W ("%p socks5 unix path", self);
        return -1;
    }

    addr.sun_family = AF_UNIX;
    memcpy (addr.sun_path, path, path_len + 1);

    fd = socket (AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        LOG_W ("%p socks5 unix socket", self);
        return -1;
    }

    klass = HEV_OBJECT_GET_CLASS (self);
    res = HEV_SOCKS5_CLASS (klass)->binder (HEV_SOCKS5 (self), fd,
                                            (struct sockaddr *)&addr);
    if (res < 0) {
        LOG_W ("%p socks5 unix bind", self);
        hev_task_del_fd (hev_task_self (), fd);
        close (fd);
        return -1;
    }

    res = hev_task_io_socket_connect (fd, (struct sockaddr *)&addr,
                                      sizeof (sa_family_t) + path_len + 1,
                                      hev_socks5_task_io_yielder, self);
    if (res < 0) {
        LOG_I ("%p socks5 unix connect", self);
        hev_task_del_fd (hev_task_self (), fd);
        close (fd);
        return -1;
    }

    HEV_SOCKS5 (self)->fd = fd;

    return 0;
}

void
hev_socks5_session_run (HevSocks5Session *self)
{
    HevSocks5SessionIface *iface;
    HevConfigServer *srv;
    int res;

    LOG_D ("%p socks5 session run", self);

    srv = hev_config_get_socks5_server ();

    if (srv->unix_path[0])
        res = hev_socks5_session_connect_unix (self, srv->unix_path);
    else
        res = hev_socks5_client_connect (HEV_SOCKS5_CLIENT (self), srv->addr,
                                         srv->port);
    if (res < 0) {
        LOG_I ("%p socks5 session connect", self);
        return;
    }

    if (srv->user && srv->pass) {
        hev_socks5_client_set_auth (HEV_SOCKS5_CLIENT (self), srv->user,
                                    srv->pass);
        LOG_D ("%p socks5 client auth %s:%s", self, srv->user, srv->pass);
    }

    res = hev_socks5_client_handshake (HEV_SOCKS5_CLIENT (self), srv->pipeline);
    if (res < 0) {
        LOG_I ("%p socks5 session handshake", self);
        return;
    }

    iface = HEV_OBJECT_GET_IFACE (self, HEV_SOCKS5_SESSION_TYPE);
    iface->splicer (self);
}

void
hev_socks5_session_terminate (HevSocks5Session *self)
{
    HevSocks5SessionIface *iface;

    LOG_D ("%p socks5 session terminate", self);

    iface = HEV_OBJECT_GET_IFACE (self, HEV_SOCKS5_SESSION_TYPE);
    hev_socks5_set_timeout (HEV_SOCKS5 (self), 0);
    hev_task_wakeup (iface->get_task (self));
}

void
hev_socks5_session_set_task (HevSocks5Session *self, HevTask *task)
{
    HevSocks5SessionIface *iface;

    iface = HEV_OBJECT_GET_IFACE (self, HEV_SOCKS5_SESSION_TYPE);
    iface->set_task (self, task);
}

HevListNode *
hev_socks5_session_get_node (HevSocks5Session *self)
{
    HevSocks5SessionIface *iface;

    iface = HEV_OBJECT_GET_IFACE (self, HEV_SOCKS5_SESSION_TYPE);
    return iface->get_node (self);
}

void *
hev_socks5_session_iface (void)
{
    static char type;

    return &type;
}
