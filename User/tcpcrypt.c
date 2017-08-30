//
//  main.c
//  tcpcrypt
//
//  Created by Romeo Bellon on 18/08/2017.
//  Copyright © 2017 Romeo Bellon. All rights reserved.
//

#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <sys/mbuf.h>

#include "tcpcrypt.h"

static struct ti_cipher_spec _pkey[MAX_CIPHERS];
static int _pkey_len;
static struct ti_scipher _sym[MAX_CIPHERS];
static int _sym_len;

static int so = -1;

static void init_key(mbuf_t *data)
{
    struct tcpcrypt_info *ti;
    ti = mbuf_data(data);
}

static void print(struct ctl_queue_entry *ctl_entry)
{
    printf("ctl_entry: %d", ctl_entry->action);
    
    switch (ctl_entry->action) {
        case INIT_KEY:
            init_key(&ctl_entry->data);
            break;
            
        default:
            break;
    }
}

static void SignalHandler(int sigraised)
{
    // printf may be unsupported function call from a signal handler
    printf("Tcpcrypt interrupted - %d\n", sigraised);

    if (so > 0)
    {
        printf("closing socket %d\n", so);
        
        // per man 2 sigaction, close can be invoked from a signal-catching function
        close(so);
    }
    
    // exit(0) should not be called from a signal handler.  Use _exit(0) instead
    _exit(0);
}

static void usage(const char *s)
{
    printf("Tcpcrypt usage: %s [-m] [-v] [-s] [-q] [-Q max] [-E] [-F]\n\n", s);
    
    printf("tcplog is used to control the tcplognke kernel extension\n");
    printf("The command takes the following options that are evaluated in order, \n");
    printf("and several options may be combined:\n");
    printf(" %-10s%s\n", "-h", "display this help and exit");
    printf(" %-10s%s\n", "-s", "get statistics");
    printf(" %-10s%s\n", "-Q max", "set size of queue for pending log entries");
    printf(" %-10s%s\n", "-q", "get size of queue for pending log entries");
    printf(" %-10s%s\n", "-L n", "set log of tcplognke KEXT on (n > 0) or off (n = 0)");
    printf(" %-10s%s\n", "-E n", "enable log on (n > 0) or off (n = 0)");
    printf(" %-10s%s\n", "-F", "flush pending log entries");
    printf(" %-10s%s\n", "-b n", "use banner once (n < 0), never (n = 0), or every n lines");
    printf(" %-10s%s\n", "-m", "display TCP log entries");
}

int main(int argc, char * const *argv)
{
    sig_t old_handler;
    struct ctl_info ctl_info;
    struct sockaddr_ctl addr;
    int result, c;
    ssize_t n;
    struct ctl_queue_entry ctl_entry;
    
    // Set up a signal handler so we can clean up when we're interrupted from the command line
    // Otherwise we stay in our run loop forever.
    old_handler = signal(SIGINT, SignalHandler);
    if (old_handler == SIG_ERR)
        printf("Could not establish new signal handler");
    
    while ((c = getopt(argc, argv, "h")) != -1) {
        switch(c) {
            case 'h':
                usage(argv[0]);
                exit(0);
            default:
                usage(argv[0]);
                exit(-1);
        }
    }
    
    // open a PF_SYSTEM socket
    so = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (so < 0) {
        fprintf(stderr, "failed to open socket");
        exit(0);
    }
    
    // init kernel control struct
    bzero(&ctl_info, sizeof(struct ctl_info));
    strcpy(ctl_info.ctl_name, TCPCRYPT_BUNDLE_ID);
    
    /*
     * In the case of a dynamically-generated control ID, we must obtain the value for sc_id using
     * the CTLIOCGINFO ioctl. When using a dynamically-generated control ID, the unit number is
     * ignored. The stack will automatically pick an unused unit number and fill in the sc_unit
     * field before passing the connect call to the kernel control’s connect callback. While the
     * kernel side must keep track of the unit number for sending data back to the client, from the
     * client’s perspective, the unit number is unused.
     */
    if (ioctl(so, CTLIOCGINFO, &ctl_info) == -1) {
        perror("ioctl CTLIOCGINFO");
        exit(0);
    } else
        printf("ctl_id: 0x%x for ctl_name: %s\n", ctl_info.ctl_id, ctl_info.ctl_name);
    
    // init sockaddr_ctl
    bzero(&addr, sizeof(struct sockaddr_ctl));
    addr.sc_len = sizeof(struct sockaddr_ctl);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = SYSPROTO_CONTROL;
    addr.sc_id = ctl_info.ctl_id;
    addr.sc_unit = 0;
    
    // associate the socket with a particular kernel control
    result = connect(so, (struct sockaddr *)&addr, sizeof(struct sockaddr_ctl));
    if (result) {
        fprintf(stderr, "connect failed %d\n", result);
        exit(0);
    }
    
    while ((n = recv(so, &ctl_entry, sizeof(ctl_entry), 0)) == sizeof (ctl_entry))
    {
        print(&ctl_entry);
    }
    
    // init locks
    pthread_mutex_t ciphers_list_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_init(&ciphers_list_mutex, NULL);
    
    struct ciphers_list_head ciphers_list;
    struct ciphers_pkey_head ciphers_pkey;
    struct ciphers_sym_head ciphers_sym;
    
    // init queues
    TAILQ_INIT(&ciphers_list);
    TAILQ_INIT(&ciphers_pkey);
    TAILQ_INIT(&ciphers_sym);
    
    init_ciphers((void *) &ciphers_pkey, TYPE_PKEY);
    init_ciphers((void *) &ciphers_sym, TYPE_SYM);
    
    // register ciphers pkey and sym
    register_ciphers();
    
    // setup ciphers
    setup_ciphers();

    close(so);
    so = -1;
    
    return 0;
}
