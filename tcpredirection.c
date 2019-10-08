#include "ulog/ulog.h"
#include "wsocket/wsocket.h"
#include "wsocket/utils/tcpcli.h"
#include "queue/queue.h"

#include <ev.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stddef.h>
#include <signal.h>
#include <stdbool.h>
#include <ctype.h>


#define WHITELIST_FILE  "ip.txt"
#define REDIRECT_FILE   "tr.txt"

struct tr_master;
struct tr_conn;

struct tr_client {
    ev_io   io;
    wsocket socket;
    int     port;
    char    ip[64];

    unsigned char cache[1024];
    int cache_idx;
    struct  tr_conn *conn;
    struct  tr_master *master;
    TAILQ_ENTRY(tr_client) ENTRIES;
};

struct tr_conn {
    struct tcpcli cli;
    TAILQ_ENTRY(tr_conn) ENTRIES;
};


struct tr_listener {
    ev_io   io;
    wsocket socket;
    int     port;

    char    target_addr[64];
    int     target_port;

    struct  tr_master *master;
    TAILQ_ENTRY(tr_listener) ENTRIES;
};

struct tr_master {
    ev_stat stat_whitelist;
    int     whitelist_cnt;
    char    whitelist_ip[32][32];

    TAILQ_HEAD(, tr_listener)   listeners_head;
    TAILQ_HEAD(, tr_client)     clients_head;
};


static wsocket listen_on(const char *addr, const char* service)
{
    wsocket sock = INVALID_WSOCKET;

    struct addrinfo hints = {0};
    hints.ai_family = PF_UNSPEC;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    int rv = 0;
    struct addrinfo *ai = NULL;
    if ((rv = getaddrinfo(addr, service, &hints, &ai)) != 0) {
        LOG_ERROR("getaddrinfo() error, %s", gai_strerror(rv));
        return INVALID_WSOCKET;
    }
    for (const struct addrinfo *p = ai; p != NULL; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (wsocket_set_nonblocking(sock) == WSOCKET_ERROR) {
            LOG_ERROR("set nonblocking error, %s", wsocket_strerror(wsocket_errno));
            wsocket_close(sock);
            return INVALID_WSOCKET;
        }
        if (sock == INVALID_WSOCKET) {
            continue;
        }
        // enable addr resuse
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&(int){1}, sizeof(int));
        if (bind(sock, p->ai_addr, p->ai_addrlen) == WSOCKET_ERROR) {
            // bind error
            wsocket_close(sock);
            sock = INVALID_WSOCKET;
            continue;
        }
        // Got it!
        break;
    }

    if (sock == INVALID_WSOCKET) {
        LOG_ERROR("socket() or bind() error, %s", wsocket_strerror(wsocket_errno));
        freeaddrinfo(ai);
        ai = NULL;
        return INVALID_WSOCKET;
    }

    freeaddrinfo(ai);
    ai = NULL;

    if (listen(sock, 2) == WSOCKET_ERROR) {
        LOG_ERROR("listen() error, %s", wsocket_strerror(wsocket_errno));
        wsocket_close(sock);
        return INVALID_WSOCKET;
    }

    return sock;
}

// only cleanup agent and conn resource
static void close_client(EV_P_ struct tr_client *client)
{
    LOG_INFO("close client(%d) from %s", client->socket, client->ip);
    ev_io_stop(EV_A_ &client->io);
    wsocket_close(client->socket);
    free(client);
}

static void master_close_client(EV_P_ struct tr_client *client)
{
    LOG_INFO("remove client(%d ip=%s) from clients list", client->socket, client->ip);
    TAILQ_REMOVE(&client->master->clients_head, client, ENTRIES);
    if (client->conn) {
        LOG_INFO("close client(%d ip=%s)'s remote connection", client->socket, client->ip);
        tcpcli_close(&client->conn->cli);
        free(client->conn);
    }
    close_client(EV_A_ client);
}

static void client_read_cb(EV_P_ ev_io *w, int revents)
{
    struct tr_client *client = (struct tr_client *)w;

    char buf[512];
    int n = recv(client->socket, buf, sizeof(buf), 0);
    if (n == WSOCKET_ERROR && wsocket_errno != WSOCKET_EAGAIN) {
        LOG_INFO("client(%d ip=%s) recv error, %s",
                 client->socket, client->ip, wsocket_strerror(wsocket_errno));
        master_close_client(EV_A_ client);
        return;
    }
    if (n == 0) {
        LOG_INFO("client(%d ip=%s) connection close", client->socket, client->ip);
        master_close_client(EV_A_ client);
        return;
    }
    if (n < 0) { // maybe -1 since WSOCKET_EAGAIN
        return;
    }
    if (tcpcli_isconnected(&client->conn->cli)) {
        if (tcpcli_write(&client->conn->cli, buf, n) < 0) {
            LOG_INFO("client(%d ip=%s) remote connection write error",
                     client->socket, client->ip);
            master_close_client(EV_A_ client);
            return;
        }
    } else {
        if (n + client->cache_idx < sizeof(client->cache)) {
            memcpy(client->cache + client->cache_idx, buf, n);
            client->cache_idx += n;
        } else {
            LOG_INFO("client(%d ip=%s) cache full", client->socket, client->ip);
            master_close_client(EV_A_ client);
            return;
        }
    }
}

static void listener_accept_cb(EV_P_ ev_io *w, int revents)
{
    struct tr_listener *listener = (struct tr_listener *)w;
    struct tr_master *master = listener->master;

    wsocket sock = INVALID_WSOCKET;
    struct sockaddr_storage conn_addr = {0};
    socklen_t conn_addrlen = sizeof(conn_addr);

    sock = accept(listener->socket, (struct sockaddr *)&conn_addr, &conn_addrlen);
    if (sock == INVALID_WSOCKET) {
        LOG_ERROR("listener(port=%d) accept() error, %s",
                  listener->port, wsocket_strerror(wsocket_errno));
        return;
    }
    wsocket_set_nonblocking(sock);

    char addrbuf[NI_MAXHOST] = {0};
    char servbuf[NI_MAXSERV] = {0};
    int rv = 0;
    if ((rv = getnameinfo((struct sockaddr *)&conn_addr, conn_addrlen,
                          addrbuf, sizeof(addrbuf),
                          servbuf, sizeof(servbuf),
                          NI_NUMERICHOST | NI_NUMERICSERV)) == 0) {
        LOG_INFO("listener(port=%d) accept client(%d ip=%s)",
                 listener->port, sock, addrbuf);

    } else {
        LOG_ERROR("listener(port=%d) getnameinfo() error, %s",
                  listener->port, gai_strerror(rv));
    }

    // check ip if is in whitelist
    bool allow = false;
    if (strcmp(addrbuf, "127.0.0.1") == 0) {
        allow = true;
    } else {
        for (int i = 0; i < master->whitelist_cnt; i++) {
            if (strcmp(master->whitelist_ip[i], addrbuf) == 0) {
                allow = true;
            }
        }
    }
    if (!allow) {
        LOG_WARN("client(%d, ip=%s) is not in ip whitelist, reject it",
                 sock, addrbuf);
        wsocket_close(sock);
        return;
    }

    struct tr_client *client = malloc(sizeof(*client));
    if (client == NULL) {
        LOG_ERROR("malloc() error, %s", strerror(errno));
        wsocket_close(sock);
        return;
    }
    // TODO: create target tcpcli link
    struct tr_conn *conn = malloc(sizeof(*conn));
    if (conn == NULL) {
        LOG_ERROR("malloc() error, %s", strerror(errno));
        free(client);
        wsocket_close(sock);
        return;
    }
    tcpcli_init(&conn->cli, 5.0, -1, -1);
    if (tcpcli_open(&conn->cli, listener->target_addr, listener->target_port) != 0) {
        LOG_ERROR("tcpcli_open() addr=%s port=%d failed",
                  listener->target_addr, listener->target_port);
        free(conn);
        free(client);
        wsocket_close(sock);
        return;
    }
    LOG_INFO("client(%d ip=%s) create tcp(%s:%d) OK",
             client->socket, client->ip, listener->target_addr, listener->target_port);
    client->socket = sock;
    client->port = listener->port;
    snprintf(client->ip, sizeof(client->ip), addrbuf);
    client->conn = conn;
    client->master = master;
    client->cache_idx = 0;

    ev_io_init(&client->io, client_read_cb, WSOCKET_GET_FD(client->socket), EV_READ);
    ev_io_start(EV_A_  &client->io);
    LOG_INFO("move client(%d ip=%s) to clientss list", client->socket, client->ip);
    TAILQ_INSERT_TAIL(&master->clients_head, client, ENTRIES);
}



static void stat_whitelist_cb(EV_P_ ev_stat *w, int revents)
{
    struct tr_master *master = (struct tr_master *)((char *)w - offsetof(struct tr_master, stat_whitelist));
    int cnt = 0;
    FILE *fp = fopen(WHITELIST_FILE, "r");
    if (fp) {
        char line[64];
        while (fgets(line, sizeof(line), fp) &&
               cnt < sizeof(master->whitelist_ip) / sizeof(master->whitelist_ip[0])) {
            char *p = line;
            while (isspace(*p)) p++;
            if (p[0] == '\0' || p[0] == '#' || p[0] == ';') {
                continue;
            }
            char *q = p + strlen(p) - 1;
            while (isspace(*q)) q--;
            *(q + 1) = '\0';
            LOG_TRACE("whitelist ip: %s", p);
            snprintf(master->whitelist_ip[cnt], sizeof(master->whitelist_ip[cnt]), "%s", p);
            cnt += 1;
        }
    } else {
        LOG_WARN("cannot open ip.txt, %s", strerror(errno));
    }
    master->whitelist_cnt = cnt;
    LOG_INFO("fetch %d ip from ip.txt", cnt);
}

static int log_print(void *userdata, int tag, const char *line)
{
    printf("%s", line);
    if (userdata) {
        FILE *fp = userdata;
        fputs(line, fp);
        fflush(fp);
    }
}

int main(int argc, const char *argv[])
{
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
    ulog_init_default(argv[0]);

    WSOCKET_INIT();

    struct ev_loop* loop = EV_DEFAULT;
    static struct tr_master master = {0};
    TAILQ_INIT(&master.listeners_head);
    TAILQ_INIT(&master.clients_head);

    FILE* fp = fopen(REDIRECT_FILE, "r");
    if (!fp) {
        LOG_ERROR("cannot open redirecion file '%s', %s", REDIRECT_FILE, strerror(errno));
        return 1;
    }
    char line[128];
    int lo = 0;
    while (fgets(line, sizeof(line), fp)) {
        int port;
        char tar_addr[32];
        int  tar_port;
        lo += 1;
        if (line[0] == '\0') {
            continue;
        }
        if (sscanf(line, "%d %31s %d", &port, tar_addr, &tar_port) < 3) {
            LOG_ERROR("invalid format in redirection file '%s', line %d",
                     REDIRECT_FILE, lo);
            return 1;
        }
        if (port < 1 || port > 65535 || tar_port < 1 || tar_port > 65535) {
            LOG_ERROR("invalid port in redirection file '%s', line %d",
                      REDIRECT_FILE, lo);
            return 1;
        }
        LOG_INFO("redirect 0.0.0.0:%d to %s:%d", port, tar_addr, tar_port);

        char serv[16];
        snprintf(serv, sizeof(serv), "%d", port);
        wsocket sock = listen_on("0.0.0.0", serv);
        if (sock == INVALID_WSOCKET) {
            LOG_ERROR("setup server on 0.0.0.0:%s error.", serv);
            return 1;
        }
        LOG_INFO("setup server on 0.0.0.0:%s OK.", serv);
        struct tr_listener *listener = calloc(1, sizeof(struct tr_listener));
        if (listener == NULL) {
            LOG_ERROR("malloc error, %s", strerror(errno));
            return 1;
        }
        listener->socket = sock;
        listener->port = port;
        listener->master = &master;
        snprintf(listener->target_addr, sizeof(listener->target_addr), "%s", tar_addr);
        listener->target_port = tar_port;
        ev_io_init(&listener->io, listener_accept_cb, WSOCKET_GET_FD(sock), EV_READ);
        ev_io_start(EV_A_ &listener->io);
        TAILQ_INSERT_TAIL(&master.listeners_head, listener, ENTRIES);
    }

    ev_stat_init(&master.stat_whitelist, stat_whitelist_cb, WHITELIST_FILE, 0);
    ev_stat_start(EV_A_ &master.stat_whitelist);

    ev_invoke(EV_A_ &master.stat_whitelist, 0);
    while (1) {
        usleep(1000);
        ev_loop(loop, EVRUN_NOWAIT);
        struct tr_client *client, *tmp;
        TAILQ_FOREACH_SAFE(client, &master.clients_head, ENTRIES, tmp) {
            if (client->cache_idx > 0 && tcpcli_isconnected(&client->conn->cli)) {
                tcpcli_write(&client->conn->cli, client->cache, client->cache_idx);
                client->cache_idx = 0;
            }
            char buf[512];
            int rd = tcpcli_read(&client->conn->cli, buf, sizeof(buf));
            if (rd > 0) {
                if (send(client->socket, buf, rd, 0) <= 0) {
                    LOG_INFO("client(%d ip=%s) send error, %s",
                             client->socket, client->ip, wsocket_strerror(wsocket_errno));
                    master_close_client(EV_A_ client);
                }
            } else if (rd < 0) {
                LOG_INFO("client(%d ip=%s) remote connection read error",
                         client->socket, client->ip);
                master_close_client(EV_A_ client);
            }
        }
    }
    WSOCKET_CLEANUP();
    return 1;
}
