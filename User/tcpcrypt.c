//
//  main.c
//  tcpcrypt
//
//  Created by Romeo Bellon.
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
#include <sys/kernel_types.h>
#include <sys/buf.h>

#include <arpa/inet.h>

#include "tcpcrypt.h"

static struct ti_cipher_spec _pkey[MAX_CIPHERS];
static int _pkey_len;
static struct ti_scipher _sym[MAX_CIPHERS];
static int _sym_len;

struct ciphers ciphers_pkey;
struct ciphers ciphers_sym;

static int so = -1;

static int ctl_send_to_so(struct ctl_data *ctl_data)
{
    printf("ctl_set_option, sending %zu\n", sizeof(*ctl_data));
    
    int result = 0;
    
    if (send(so, ctl_data, sizeof(*ctl_data), 0) != sizeof(*ctl_data))
        return -1;
    
    return result;
}

static void do_random(void *p, int len) {
    uint8_t *x = p;
    
    while (len--)
    {
        *x++ = getRandomByte();// & 0xff;
        printf("do_random: %d", getRandomByte());
    }
}

static void generate_nonce(struct tcpcrypt_info *ti, int len) {
    assert(ti->ti_nonce_len == 0);
    
    ti->ti_nonce_len = len;
    
    do_random(ti->ti_nonce, ti->ti_nonce_len);
}

static void init_ti(struct ctl_data *ctl_data)
{
    ctl_data->c_ti.ti_ciphers_pkey = _pkey;
    ctl_data->c_ti.ti_ciphers_pkey_len = _pkey_len;
    ctl_data->c_ti.ti_ciphers_sym = _sym;
    ctl_data->c_ti.ti_ciphers_sym_len = _sym_len;
//    generate_nonce(ti, ti->ti_crypt_pub->cp_n_c);
    
    if (ctl_send_to_so(ctl_data))
        perror("Error while setting option!\n");
}

static void init_pkey(struct tcpcrypt_info *ti)
{
    init_ti(ti);
//    lck_mtx_lock(ciphers_mutex);
//
//    struct ciphers *c, *c_next;
//    struct ti_cipher_spec *s;
//
//    assert(tc->tc_cipher_pkey.tcs_algo);
//
//    for (c = TAILQ_FIRST(&ciphers_pkey); c != NULL; c = c_next)
//    {
//        c_next = TAILQ_NEXT(c, c_next);
//
//        s = (struct ti_cipher_spec *) c->c_spec;
//
//        if (s->tcs_algo == ti->ti_cipher_pkey.tcs_algo) {
//            ti->ti_crypt_pub = crypt_new(c->c_cipher->c_ctr);
//            return;
//        }
//    }
//
//    lck_mtx_unlock(ciphers_mutex);
}

static void handle_ctl_data(struct ctl_data *ctl_data)
{
    printf("been here ctl_data->c_action %d\n", ctl_data->c_action);
    switch (ctl_data->c_action) {
        case INIT_TI:
            init_ti(ctl_data);
            break;

        case INIT_PKEY:
            printf("INIT_PKEY, direction %d\n", ctl_data->c_ti.ti_dir);
//            init_pkey((struct tcpcrypt_info *) &ctl_data->c_data);
            break;

        default:
            printf("handle_ctl_data: unknown action %d\n", ctl_data->c_action);
            break;
    }
}

static void do_register_cipher(struct ciphers *c, struct cipher *cl)
{
    struct ciphers *x;
    
    x = malloc(sizeof(*x));
    bzero(x, sizeof(*x));
    x->c_cipher = cl;
    
    while (c->c_next) {
        c = c->c_next;
    }
    
    // adding at the end
    x->c_next = c->c_next;
    c->c_next = x;
    
    printf("crypto: 0x%x registered\n", x->c_cipher->c_id);
}

void setup_cipher(struct cipher *c)
{
    int type = c->c_type;
    
    switch (type) {
        case TYPE_PKEY:
            do_register_cipher(&ciphers_pkey, c);
            break;
            
        case TYPE_SYM:
            do_register_cipher(&ciphers_sym, c);
            break;
            
        default:
            assert(!"Unknown type");
            break;
    }
    
    fflush(stdout);
}

static void SignalHandler(int sigraised)
{
    // printf may be unsupported function call from a signal handler
    printf("\nTcpcrypt interrupted - %d\n", sigraised);

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
    
    printf("tcpcrypt is used to control the Tcpcrypt kernel extension.\n");
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
    int c;
    ssize_t n;
    struct ctl_data ctl_data;
    
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
        printf("ioctl: couldn't connect to the kernel extension\n");
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
    if (connect(so, (struct sockaddr *)&addr, sizeof(struct sockaddr_ctl))) {
        perror("connect");
        exit(0);
    }
    
    // init locks
    pthread_mutex_t ciphers_list_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_init(&ciphers_list_mutex, NULL);
    
    // register ciphers pkey and sym
    register_ciphers();
    
    // add ciphers
    struct cipher *ci = get_ciphers();
    
    while (ci) {
        setup_cipher(ci);
        ci = ci->c_next;
    }
    
    init_cipher(&ciphers_pkey);
    init_cipher(&ciphers_sym);

    do_add_ciphers(&ciphers_pkey, &_pkey, &_pkey_len, sizeof(*_pkey),
                   (uint8_t *) _pkey + sizeof(_pkey));
    do_add_ciphers(&ciphers_sym, &_sym, &_sym_len, sizeof(*_sym),
                   (uint8_t *) _sym + sizeof(_sym));
    
    while ((n = recv(so, &ctl_data, sizeof(ctl_data), 0)) == sizeof(ctl_data))
    {
        handle_ctl_data(&ctl_data);
    }

    close(so);
    so = -1;
    
    return 0;
}
