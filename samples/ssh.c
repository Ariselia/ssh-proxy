/* client.c */
#include "ssh-includes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/select.h>
#include <sys/time.h>

#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_PTY_H
#include <pty.h>
#endif

#include <sys/ioctl.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>

#include <ssh/callbacks.h>
#include <ssh/ssh-api.h>
#include <ssh/sftp.h>


#include "examples_common.h"
#define MAXCMD 10

static char *host;
static char *user;
static char *cmds[MAXCMD];
static struct termios terminal;

static char *proxycommand;

static int auth_callback(const char *prompt, char *buf, size_t len,
                         int echo, int verify, void *userdata)
{
    (void) verify;
    (void) userdata;

    return ssh_getpass(prompt, buf, len, echo, verify);
}

struct ssh_callbacks_struct cb =
{
    .auth_function=auth_callback,
    .userdata=NULL
};

static void add_cmd(char *cmd)
{
    int n;

    for (n = 0; (n < MAXCMD) && cmds[n] != NULL; n++);

    if (n == MAXCMD)
    {
        return;
    }
    cmds[n]=strdup(cmd);
}

static void usage()
{
    fprintf(stderr,"Usage : ssh [options] [login@]hostname\n"
            "sample client - libssh-%s\n"
            "Options :\n"
            "  -l user : log in as user\n"
            "  -p port : connect to port\n"
            "  -d : use DSS to verify host public key\n"
            "  -r : use RSA to verify host public key\n"
#ifndef _WIN32
            "  -T proxycommand : command to execute as a socket proxy\n"
#endif
            ,
            ssh_version(0));
    exit(0);
}

static int opts(int argc, char **argv)
{
    int i;
//    for(i=0;i<argc;i++)
//        printf("%d : %s\n",i,argv[i]);
    /* insert your own arguments here */
    while((i=getopt(argc,argv,"T:P:"))!=-1)
    {
        switch(i)
        {
#ifndef _WIN32
            case 'T':
                proxycommand=optarg;
                break;
#endif
            default:
                fprintf(stderr,"unknown option %c\n",optopt);
                usage();
        }
    }
    if(optind < argc)
        host=argv[optind++];
    while(optind < argc)
        add_cmd(argv[optind++]);
    if(host==NULL)
        usage();
    return 0;
}

#ifndef HAVE_CFMAKERAW
static void cfmakeraw(struct termios *termios_p)
{
    termios_p->c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
    termios_p->c_oflag &= ~OPOST;
    termios_p->c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
    termios_p->c_cflag &= ~(CSIZE|PARENB);
    termios_p->c_cflag |= CS8;
}
#endif


static void do_cleanup(int i)
{
    /* unused variable */
    (void) i;

    tcsetattr(0,TCSANOW,&terminal);
}

static void do_exit(int i)
{
    /* unused variable */
    (void) i;

    do_cleanup(0);
    exit(0);
}

ssh_channel_t *chan;
int signal_delayed=0;

static void sigwindowchanged(int i)
{
    (void) i;
    signal_delayed=1;
}

static void setsignal(void)
{
    signal(SIGWINCH, sigwindowchanged);
    signal_delayed=0;
}

static void sizechanged(void)
{
    struct winsize win = { 0, 0, 0, 0 };
    ioctl(1, TIOCGWINSZ, &win);
    ssh_channel_change_pty_size(chan,win.ws_col, win.ws_row);
//    printf("Changed pty size\n");
    setsignal();
}

static void select_loop(ssh_session_t *session,ssh_channel_t *channel)
{
    fd_set fds;
    struct timeval timeout;
    char buffer[4096];
    /* channels will be set to the channels to poll.
     * outchannels will contain the result of the poll
     */
    ssh_channel_t *channels[2], *outchannels[2];
    int lus;
    int eof=0;
    int maxfd;
    unsigned int r;
    int ret;
    while(channel)
    {
        do
        {
            FD_ZERO(&fds);
            if(!eof)
            {
                FD_SET(0, &fds);
            }
            timeout.tv_sec = 30;
            timeout.tv_usec = 0;
            FD_SET(ssh_get_fd(session), &fds);
            maxfd = ssh_get_fd(session) + 1;
            channels[0] = channel; // set the first channel we want to read from
            channels[1] = NULL;
            ret = ssh_select(channels, outchannels, maxfd, &fds, &timeout);
            if(signal_delayed)
            {
                sizechanged();
            }
            if(ret == EINTR)
            {
                continue;
            }
            if(FD_ISSET(0, &fds))
            {
                lus = read(0, buffer, sizeof(buffer));
                if(lus)
                    ssh_channel_write(channel, buffer, lus);
                else
                {
                    eof = 1;
                    ssh_channel_send_eof(channel);
                }
            }
            if(channel && ssh_channel_is_closed(channel))
            {
                ssh_channel_free(channel);
                channel=NULL;
                channels[0]=NULL;
            }
            if(outchannels[0])
            {
                while(channel && ssh_channel_is_open(channel) && (r = ssh_channel_poll(channel,0))!=0)
                {
                    lus = ssh_channel_read(channel,buffer,sizeof(buffer) > r ? r : sizeof(buffer),0);
                    if(lus == -1)
                    {
                        fprintf(stderr, "Error reading channel: %s\n",
                                ssh_get_error(session));
                        return;
                    }
                    if(lus == 0)
                    {
                        ssh_channel_free(channel);
                        channel=channels[0]=NULL;
                    }
                    else
                    {
                        if (write(1,buffer,lus) < 0)
                        {
                            fprintf(stderr, "Error writing to buffer\n");
                            return;
                        }
                    }
                }
                while(channel && ssh_channel_is_open(channel) && (r = ssh_channel_poll(channel,1))!=0)  /* stderr */
                {
                    lus = ssh_channel_read(channel,buffer,sizeof(buffer) > r ? r : sizeof(buffer),1);
                    if(lus == -1)
                    {
                        fprintf(stderr, "Error reading channel: %s\n",
                                ssh_get_error(session));
                        return;
                    }
                    if(lus == 0)
                    {
                        ssh_channel_free(channel);
                        channel = channels[0] = NULL;
                    }
                    else
                    {
                        if (write(2, buffer, lus) < 0)
                        {
                            fprintf(stderr, "Error writing to buffer\n");
                            return;
                        }
                    }
                }
            }
            if(channel && ssh_channel_is_closed(channel))
            {
                ssh_channel_free(channel);
                channel=NULL;
            }
        }
        while (ret == EINTR || ret == SSH_EINTR);

    }
}

static void shell(ssh_session_t *session)
{
    ssh_channel_t *channel;
    struct termios terminal_local;
    int interactive=isatty(0);
    channel = ssh_channel_new(session);
    if(interactive)
    {
        tcgetattr(0,&terminal_local);
        memcpy(&terminal,&terminal_local,sizeof(struct termios));
    }
    if(ssh_channel_open_session(channel))
    {
        printf("error opening channel : %s\n",ssh_get_error(session));
        return;
    }
    chan = channel;
    if(interactive)
    {
        ssh_channel_request_pty(channel);
        sizechanged();
    }
    if(ssh_channel_request_shell(channel))
    {
        printf("Requesting shell : %s\n", ssh_get_error(session));
        return;
    }
    if(interactive)
    {
        cfmakeraw(&terminal_local);
        tcsetattr(0,TCSANOW,&terminal_local);
        setsignal();
    }
    signal(SIGTERM,do_cleanup);
    select_loop(session,channel);
    if(interactive) {
        do_cleanup(0);
    }
}

static void batch_shell(ssh_session_t *session)
{
    ssh_channel_t *channel;
    char buffer[1024];
    int i, s = 0;
    for(i = 0; i < MAXCMD && cmds[i]; ++i)
    {
        s += snprintf(buffer + s,sizeof(buffer) - s, "%s ", cmds[i]);
        free(cmds[i]);
        cmds[i] = NULL;
    }
    channel = ssh_channel_new(session);
    ssh_channel_open_session(channel);
    if(ssh_channel_request_exec(channel, buffer))
    {
        printf("error executing \"%s\" : %s\n", buffer, ssh_get_error(session));
        return;
    }
    select_loop(session,channel);
}

static int client(ssh_session_t *session)
{
    int auth=0;
    char *banner;
    int state;
    if (user)
    {
        if (ssh_options_set(session, SSH_OPTIONS_USER, user) < 0)
        {
            return -1;
        }
    }
    if (ssh_options_set(session, SSH_OPTIONS_HOST ,host) < 0)
    {
        return -1;
    }
    if (proxycommand != NULL)
    {
        if(ssh_options_set(session, SSH_OPTIONS_PROXYCOMMAND, proxycommand))
        {
            return -1;
        }
    }
    ssh_options_parse_config(session, NULL);

    if(ssh_connect(session))
    {
        fprintf(stderr,"Connection failed : %s\n",ssh_get_error(session));
        return -1;
    }
    state = verify_knownhost(session);
    if (state != 0)
    {
        return -1;
    }
    ssh_userauth_none(session, NULL);
    banner = ssh_get_issue_banner(session);
    if(banner)
    {
        printf("%s\n", banner);
        free(banner);
    }
    auth = authenticate_console(session);
    if(auth != SSH_AUTH_SUCCESS)
    {
        return -1;
    }
    if(!cmds[0]) {
        shell(session);
    } else {
        batch_shell(session);
    }
    return 0;
}

int main(int argc, char **argv)
{
    ssh_session_t *session = NULL;

    session = ssh_new();

    ssh_callbacks_init(&cb);
    ssh_set_callbacks(session,&cb);

    if(ssh_options_getopt(session, &argc, argv))
    {
        fprintf(stderr, "error parsing command line :%s\n",
                ssh_get_error(session));
        usage();
    }
    opts(argc,argv);
    signal(SIGTERM, do_exit);

    client(session);

    ssh_disconnect(session);
    ssh_free(session);

    ssh_finalize();

    return 0;
}
