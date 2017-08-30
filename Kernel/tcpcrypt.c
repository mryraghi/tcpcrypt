//
//  Kernel.c
//  Kernel
//
//  Created by Romeo Bellon on 27/08/2017.
//  Copyright © 2017 Romeo Bellon. All rights reserved.
//

#include <mach/mach_types.h>

#include "tcpcrypt.h"

struct tc_conf tc_conf;

struct ctl_list_head ctl_list;
static boolean_t ctl_registered = FALSE;

// filter vars
ipfilter_t  ip_filter_ref;
boolean_t   ip_filter_registered = FALSE;
boolean_t   ip_filter_detached =  FALSE;

// Tag associated with this kext for use in marking packets that have been
// previously processed
mbuf_tag_id_t   id_tag;

typedef int (*opt_cb)(struct tcpcrypt_info *ti, int tcpop, int len, void *data);

static int is_eno(int tcpop, void *data, int len) {
    uint16_t *exid = data;
    
    if (tcpop != TCPOPT_EXP)
        return 0;
    
    if (len < sizeof(*exid))
        return 0;
    
    if (ntohs(*exid) != EXID_ENO)
        return 0;
    
    return 1;
}

static int get_eno(int tcpop, void **data, int *len) {
    if (!is_eno(tcpop, *data, *len))
        return 0;
    
    assert(*len >= 2);
    
    *len -= 2;
    *data = ((unsigned char *) *data) + 2;
    
    return 1;
}

static void set_eno(struct tcpopt_eno *eno, int len)
{
    eno->toe_kind = TCPOPT_EXP;
    eno->toe_len = len;
    eno->toe_exid = htons(EXID_ENO);
}

static void ti_init(struct tcpcrypt_info *ti)
{
    memset(ti, 0, sizeof(*ti));
    
    ti->ti_state = tc_conf.tc_enabled ? STATE_CLOSED : STATE_DISABLED;
    ti->ti_mtu = TC_MTU;
    ti->ti_mss_clamp = 40; // TODO
    ti->ti_sack_disable = 1;
    ti->ti_rto = 100 * 1000; // TODO
    ti->ti_nocache = tc_conf.tc_nocache;
    
    ti->ti_ciphers_pkey = _pkey;
    ti->ti_ciphers_pkey_len = _pkey_len;
    ti->ti_ciphers_sym = _sym;
    ti->ti_ciphers_sym_len = _sym_len;
}

static int connected(struct tcpcrypt_info *ti) {
    return ti->ti_state == STATE_ENCRYPTING
    || ti->ti_state == STATE_REKEY_SENT
    || ti->ti_state == STATE_REKEY_RCVD;
}

struct connection* new_connection(struct ip *ip, struct tcphdr *tcp, int dir)
{
    printf("INFO - new_connection\n");
    
    struct connection *c;
    struct tcpcrypt_info *ti;
    
    c = (struct connection *)OSMalloc(sizeof (struct connection), malloc_tag);
    ti = (struct tcpcrypt_info *)OSMalloc(sizeof (struct tcpcrypt_info),
                                          malloc_tag);
    
    memset(c, 0, sizeof(*c));
    
    c->c_addr[!dir].sin_addr.s_addr = ip->ip_src.s_addr;
    c->c_addr[!dir].sin_port = tcp->th_sport;
    c->c_addr[dir].sin_addr.s_addr = ip->ip_dst.s_addr;
    c->c_addr[dir].sin_port = tcp->th_dport;
    
    ti_init(ti);
    
    // TODO: c_addr[0]?
    ti->ti_dst_ip.s_addr = c->c_addr[!dir].sin_addr.s_addr;
    ti->ti_dst_port = c->c_addr[!dir].sin_port;
    ti->ti_conn = c;
    c->c_ti = ti;
    
    // allow only a single entry into the function at a time
    lck_mtx_lock(gmutex);
    
    printf("Adding c to connections_queue\n");
    TAILQ_INSERT_HEAD(&connections_queue, c, c_next);
    
    // release lock
    lck_mtx_unlock(gmutex);
    
    return c;
}

struct connection* lookup_connection(struct ip *ip, struct tcphdr *tcp, int dir)
{
    struct connection *c, *c_next;
    struct sockaddr_in addr[2];
    
    addr[!dir].sin_addr.s_addr = ip->ip_src.s_addr;
    addr[!dir].sin_port = tcp->th_sport;
    addr[dir].sin_addr.s_addr = ip->ip_dst.s_addr;
    addr[dir].sin_port = tcp->th_dport;
    
    // protect access to the info_so_queue
    for (c = TAILQ_FIRST(&connections_queue); c != NULL; c = c_next)
    {
        // get the next element pointer
        c_next = TAILQ_NEXT(c, c_next);
        
        // not checking ports so to avoid duplicate entries in case
        // of different connections on different ports
        // return match, if found
        if (addr[!dir].sin_addr.s_addr == c->c_addr[!dir].sin_addr.s_addr
            && addr[dir].sin_addr.s_addr == c->c_addr[dir].sin_addr.s_addr)
            return c;
    }
    
    // if no such connection exists
    return 0;
}

void remove_connection(struct ip *ip, struct tcphdr *tcp, int dir)
{
    printf("remove_connection: removing connection...\n");
    
    //    struct tcpcrypt_info *ti = NULL;
    struct connection *c;
    
    c = lookup_connection(ip, tcp, dir);
    
    assert(c);
    
    // ti_finish(ti);
    
    // allow only a single entry into the function at a time
    lck_mtx_lock(gmutex);
    
    TAILQ_REMOVE(&connections_queue, c, c_next);
    OSFree(c, sizeof(struct connection), malloc_tag);
    
    // release lock
    lck_mtx_unlock(gmutex);
}

struct ti_sess *session_find_host(struct tcpcrypt_info *ti, struct in_addr *in, int port)
{
    struct ti_sess *s, *s_next;
    
    // allow only a single entry into the function at a time
    lck_mtx_lock(gmutex);
    
    // protect access to the info_so_queue
    for (s = TAILQ_FIRST(&sessions_queue); s != NULL; s = s_next)
    {
        // get the next element pointer before we potentially corrupt it
        s_next = TAILQ_NEXT(s, ts_next);
        
        if (!s->ts_used
            && (s->ts_dir == ti->ti_dir)
            && (s->ts_ip.s_addr == in->s_addr))
        {
            printf("Found session host\n");
            return s;
        }
    }
    
    // release lock
    lck_mtx_unlock(gmutex);
    
    printf("Session host NOT found\n");
    return NULL;
}

/**
 Used to scan the queue of swallowed packets and free the mbuf_t's
 that match to the input socket_t 'so' parameter. The queue item is
 also released.
 */
void free_deferred_data()
{
    lck_mtx_lock(gmutex);
    
    struct ti_sess *ts, *ts_next;
    
    // protect access to the info_so_queue
    for (ts = TAILQ_FIRST(&sessions_queue); ts != NULL; ts = ts_next)
    {
        // get the next element pointer before we potentially corrupt it
        ts_next = TAILQ_NEXT(ts, ts_next);
        
        printf("Removing 1 elem from sessions_queue\n");
        TAILQ_REMOVE(&sessions_queue, ts, ts_next);
    }
    
    struct connection *c, *c_next;
    
    // protect access to the info_so_queue
    for (c = TAILQ_FIRST(&connections_queue); c != NULL; c = c_next)
    {
        // get the next element pointer before we potentially corrupt it
        c_next = TAILQ_NEXT(c, c_next);
        
        printf("Removing 1 elem from connections_queue\n");
        
        TAILQ_REMOVE(&connections_queue, c, c_next);
        OSFree(c->c_ti, sizeof(struct tcpcrypt_info), malloc_tag);
        OSFree(c, sizeof(struct connection), malloc_tag);
    }
    
    lck_mtx_unlock(gmutex);
}

static void foreach_opt(struct tcpcrypt_info *ti, struct tcphdr *tcp, opt_cb cb) {
    unsigned char *ptr = (unsigned char *)(tcp + 1);
    int length = (tcp->th_off << 2) - sizeof(*tcp);
    
    assert(length >= 0);
    
    while (length > 0) {
        int opsize = 0, opcode = *ptr++;
        length--;
        
        switch (opcode)
        {
            case TCPOPT_EOL:
            case TCPOPT_NOP:
                continue;
                
            default:
                if (!length)
                    return;
                
                opsize = *ptr++;
                length--;
                
                if (opsize > (length + 2) || opsize < 2)
                    return ;
                
                length -= - 2;
                break;
        }
        
        if (cb(ti, opcode, opsize, ptr))
            return;
        
        ptr += opsize;
        length -= opsize;
    }
    
    assert(len == 0);
}

static int do_set_eno_transcript(struct tcpcrypt_info *ti, int tcpop, int len, void *data)
{
    uint8_t *p = &ti->ti_eno[ti->ti_eno_len];
    
    if (!is_eno(tcpop, data, len))
        return NKE_ACCEPT;
    
    assert(len + 2 + tc->tc_eno_len < sizeof(tc->tc_eno));
    
    *p++ = TCPOPT_EXP;
    *p++ = len + 2;
    
    memcpy(p, data, len);
    
    ti->ti_eno_len += 2 + len;
    
    return NKE_ACCEPT;
}

static void set_eno_transcript(struct tcpcrypt_info *ti, struct tcphdr *tcp)
{
    struct tcpopt_eno *eno;
    
    foreach_opt(ti, tcp, do_set_eno_transcript);
    
    assert(tc->tc_eno_len + sizeof(*eno) < sizeof(tc->tc_eno));
    
    eno = (struct tcpopt_eno *) &ti->ti_eno[ti->ti_eno_len];
    
    // verify here
    // set_eno(eno, sizeof(*eno));
    
    ti->ti_eno_len += sizeof(*eno);
}

static void *find_opt(struct tcphdr *tcp, unsigned char opt) {
    unsigned char *ptr = (unsigned char *)(tcp + 1);
    int length = (tcp->th_off * 4) - sizeof(struct tcphdr);
    
    assert(length >= 0);
    
    while (length > 0)
    {
        // check for an opcode match
        if (*ptr == opt) {
            // check whether the option length is not
            // greater than the remaining options length
            if (*(ptr + 1) > length)
                return NULL;
            
            printf("INFO - find_opt, found opcode # %d\n", opt);
            return ptr;
        }
        
        int opcode = *ptr++;
        length--;
        
        switch (opcode)
        {
            case TCPOPT_NOP:
            case TCPOPT_EOL:
                continue;
        }
        
        if (!length)
            return NULL;
        
        int opsize = *ptr++;
        length--;
        
        if (opsize > (length + 2) || opsize < 2)
        {
            printf("ERROR - find_opt: opsize %d, length %d\n", opsize, length);
            return NULL;
        }
        
        ptr += opsize - 2;
        length -= opsize - 2;
    }
    
    assert(length == 0);
    
    return NULL;
}

static struct tcpopt_eno *find_eno(struct tcphdr *tcp) {
    struct tcpopt_eno *eno = find_opt(tcp, TCPOPT_EXP);
    
    if (!eno)
        return NULL;
    
    assert(eno->toe_len >= 2);
    
    if (is_eno(eno->toe_kind, (unsigned char *) eno + 2, eno->toe_len - 2))
    {
        printf("YUUUUU - FOUND ENO IN INCOMING PACKET\n");
        return eno;
    }
    
    return NULL;
}

/**
 Iterate over TCP options and find space for ENO
 
 https://github.com/torvalds/linux/blob/master/net/ipv4/tcp_input.c#L3721-L3723
 */
static void *tcp_opts_alloc(struct tcpcrypt_info *ti, struct ip *ip, struct tcphdr *tcp, int len)
{
    int opslen = (tcp->th_off << 2) + len;
    int pad = opslen % 4;
    
    // pointer at the end of the options
    char *ptr = find_opt(tcp, TCPOPT_EOL);
    
    // compensate length
    if (pad)
        len += 4 - pad;
    
    /*
     * TODO: make space if full of NOPs
     */
    //    if (ol == 40) {
    //        ol = tcp_ops_len(tc, tcp);
    //        assert(ol <= 40);
    //
    //        if (40 - ol >= len)
    //            return (uint8_t * )(tcp + 1) + ol;
    //    }
    
    if (!ptr)
        return NULL;
    
    // ptr++;
    
    // make space
    memmove(ptr + len, ptr, len);
    
    // set zeroes
    bzero(ptr, len);
    
    assert(((tcp->th_off << 2) + len) <= 60);
    
    ip->ip_len = htons(ntohs(ip->ip_len) + len);
    tcp->th_off += len >> 2;
    
    return ptr;
}

static int sack_disable(struct tcpcrypt_info *ti, struct tcphdr *tcp)
{
    printf("sack_disable\n");
    
    struct {
        uint8_t kind;
        uint8_t len;
    } *sack;
    
    sack = find_opt(tcp, TCPOPT_SACK_PERMITTED);
    if (!sack)
        return NKE_ACCEPT;
    
    memset(sack, TCPOPT_NOP, sizeof(*sack));
    
    return NKE_MODIFY;
}

static int do_tcp_output(struct ip *ip, struct tcphdr *tcp, struct tcpcrypt_info *ti)
{
    printf("do_tcp_output\n");
    
    int result = NKE_ACCEPT;
    
    if (tcp->th_flags & TH_SYN)
        ti->ti_isn = ntohl(tcp->th_seq) + 1;
    
    if (tcp->th_flags == TH_SYN) {
        if (ti->ti_tcp_state == TCPSTATE_LASTACK) {
            //            tc_finish(tc);
            //            tc_reset(tc);
        }
        
        //        result = sack_disable(ti, tcp);
    }
    
    if (tcp->th_flags & TH_FIN) {
        switch (ti->ti_tcp_state) {
            case TCPSTATE_FIN1_RCVD:
                ti->ti_tcp_state = TCPSTATE_FIN2_SENT;
                break;
                
            case TCPSTATE_FIN2_SENT:
                break;
                
            default:
                ti->ti_tcp_state = TCPSTATE_FIN1_SENT;
        }
        
        return result;
    }
    
    if (tcp->th_flags & TH_RST) {
        ti->ti_tcp_state = TCPSTATE_DEAD;
        return result;
    }
    
    if (!(tcp->th_flags & TH_ACK))
        return result;
    
    switch (ti->ti_tcp_state) {
        case TCPSTATE_FIN2_RCVD:
            ti->ti_tcp_state = TCPSTATE_LASTACK;
            //            if (!ti->ti_last_ack_timer)
            //                ti->ti_last_ack_timer = add_timer(10 * 1000 * 1000, last_ack, tc);
            //            else
            //                xprintf(XP_DEFAULT, "uarning\n");
            //            break;
    }
    
    return result;
}

static errno_t do_output_closed(struct ip *ip, struct tcphdr *tcp, struct tcpcrypt_info *ti)
{
    //    struct ti_sess *ts = ti->ti_sess;
    struct tcpopt_eno *eno;
    //    struct tc_sid *sopt;
    //    uint8_t *p;
    int len;
    
    //    if (tcp->th_flags != TH_SYN)
    //        return NKE_ACCEPT;
    
    //    if (!ts && !ti->ti_nocache)
    //        ts = session_find_host(ti, &ip->ip_dst, tcp->th_dport);
    
    
    len = sizeof(*eno) + ti->ti_ciphers_pkey_len;
    
    //    if (ti->ti_app_support)
    //        len += 1;
    
    //    if (ts)
    //        len += sizeof(*sopt);
    
    printf("INFO - do_output_closed, len: %d\n", len);
    
    // pointer to end of options with enough space left for eno
    eno = tcp_opts_alloc(ti, ip, tcp, len);
    
    if (!eno) {
        printf("ERROR - do_output: no space for hello\n");
        ti->ti_state = STATE_DISABLED;
        
        // TODO: try without session resumption
        
        return NKE_DROP;
    }
    
    /*
     * Set ENO
     */
    set_eno(eno, len);
    memcpy(eno->toe_opts, ti->ti_ciphers_pkey, ti->ti_ciphers_pkey_len);
    
    //    p = eno->toe_opts + ti->ti_ciphers_pkey_len;
    
    ti->ti_state = STATE_HELLO_SENT;
    
    //    if (!ts) {
    //        //        if (!tc_conf.tc_nocache)
    //        printf("INFO - do_output_closed: can't find session for host\n");
    //    } else {
    //        printf("INFO - do_output_closed: found session for host\n");
    //
    //        /* session caching */
    //        sopt = (struct tc_sid *) p;
    //
    //        assert(ts->ts_sid.s_len >= sizeof(*sopt));
    //        memcpy(sopt, &ts->ts_sid.s_data, sizeof(*sopt));
    //
    //        ti->ti_state = STATE_NEXTK1_SENT;
    //        assert(!ts->ts_used || ts == ti->ti_sess);
    //        ti->ti_sess = ts;
    //        ts->ts_used = 1;
    //    }
    //
    ti->ti_eno_len = 0;
    //    set_eno_transcript(ti, tcp);
    
    return NKE_MODIFY;
}

static void *data_alloc(struct tcpcrypt_info *ti, struct ip *ip,
                        struct tcphdr *tcp, int len, int retx)
{
    int totlen = ntohs(ip->ip_len);
    int hl = (ip->ip_hl << 2) + (tcp->th_off << 2);
    void *p;
    
    assert(totlen == hl);
    p = (char *) tcp + (tcp->th_off << 2);
    
    totlen += len;
    assert(totlen <= 1500);
    ip->ip_len = htons(totlen);
    
    if (!retx)
        ti->ti_seq_off = len;
    
    return p;
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

static int add_eno(struct tcpcrypt_info *ti, struct ip *ip, struct tcphdr *tcp) {
    struct tcpopt_eno *eno;
    int len = sizeof(*eno);
    
    eno = tcp_opts_alloc(ti, ip, tcp, len);
    if (!eno) {
        printf("add_eno: no space for ENO\n");
        ti->ti_state = STATE_DISABLED;
        return -1;
    }
    
    set_eno(eno, len);
    
    return 0;
}

static int do_output_pkconf_rcvd(struct tcpcrypt_info *ti, struct ip *ip, struct tcphdr *tcp,
                                 int retx)
{
    int len;
    uint16_t klen;
    struct tc_init1 *init1;
    void *key;
    uint8_t *p;
    
    // add the minimal ENO option to indicate support
    if (add_eno(ti, ip, tcp) == -1)
        return NKE_ACCEPT;
    
    if (!retx)
        generate_nonce(ti, ti->ti_crypt_pub->cp_n_c);
    
    klen = crypt_get_key(ti->ti_crypt_pub->cp_pub, &key);
    len = sizeof(*init1)
    + ti->ti_ciphers_sym_len
    + ti->ti_nonce_len
    + klen;
    
    init1 = data_alloc(ti, ip, tcp, len, retx);
    
    init1->i1_magic = htonl(TC_INIT1);
    init1->i1_len = htonl(len);
    init1->i1_nciphers = ti->ti_ciphers_sym_len;
    
    p = init1->i1_data;
    
    memcpy(p, ti->ti_ciphers_sym, ti->ti_ciphers_sym_len);
    p += ti->ti_ciphers_sym_len;
    
    memcpy(p, ti->ti_nonce, ti->ti_nonce_len);
    p += ti->ti_nonce_len;
    
    memcpy(p, key, klen);
    p += klen;
    
    ti->ti_state = STATE_INIT1_SENT;
    ti->ti_role = ROLE_CLIENT;
    
    assert(len <= sizeof(tc->tc_init1));
    
    memcpy(ti->ti_init1, init1, len);
    ti->ti_init1_len = len;
    
    ti->ti_isn = ntohl(tcp->th_seq) + len;
    
    return NKE_MODIFY;
}

static int do_output(struct ip *ip, struct tcphdr *tcp, struct tcpcrypt_info *ti)
{
    printf("-----------------------   OUT   --------------------\n");
    
    int result = NKE_ACCEPT;
    int tcp_result;
    
    printf("ti->ti_state: %d\n", ti->ti_state);
    
    //    tcp_result = do_tcp_output(ip, tcp, ti);
    
    /* an RST half way through the handshake */
    //    if (ti->ti_tcp_state == TCPSTATE_DEAD && !connected(ti))
    //        return tcp_result;
    
    switch (ti->ti_state) {
        case STATE_HELLO_SENT:
        case STATE_NEXTK1_SENT:
            /* syn re-TX.  fallthrough */
            //            assert(tcp->th_flags & TH_SYN);
        case STATE_CLOSED:
            result = do_output_closed(ip, tcp, ti);
            break;
            
        case STATE_PKCONF_SENT:
            /* reTX of syn ack, or ACK (role switch) */
        case STATE_HELLO_RCVD:
            //            result = do_output_hello_rcvd(ip, tcp, ti);
            break;
            
        case STATE_NEXTK2_SENT:
            /* syn ack rtx */
            //            assert(tc->tc_sess);
            //            assert(tcp->th_flags == (TH_SYN | TH_ACK));
        case STATE_NEXTK1_RCVD:
            //            result = do_output_nextk1_rcvd(tc, ip, tcp);
            break;
            
        case STATE_PKCONF_RCVD:
            result = do_output_pkconf_rcvd(ti, ip, tcp, 0);
            break;
            
        case STATE_INIT1_RCVD:
            //            result = do_output_init1_rcvd(tc, ip, tcp);
            break;
            
        case STATE_INIT1_SENT:
            //            if (!is_init(ip, tcp, TC_INIT1))
            //                result = do_output_pkconf_rcvd(tc, ip, tcp, 1);
            break;
            
        case STATE_INIT2_SENT:
            //            result = do_output_init2_sent(tc, ip, tcp);
            break;
            
        case STATE_ENCRYPTING:
        case STATE_REKEY_SENT:
        case STATE_REKEY_RCVD:
            //            result = do_output_encrypting(tc, ip, tcp);
            break;
            
        case STATE_DISABLED:
            //            result = NKE_ACCEPT;
            break;
            
        default: break;
            //            printf("Unknown state %d", ti->ti_state);
            //abort();
    }
    
    //    if (result == NKE_ACCEPT)
    //        return tcp_result;
    
    printf("----------------------------------------------------\n");
    
    return result;
}

static int tcp_input_pre(struct ip *ip, struct tcphdr *tcp, struct tcpcrypt_info *ti) {
    int result = NKE_ACCEPT;
    
    if (tcp->th_flags & TH_SYN)
        ti->ti_isn_peer = ntohl(tcp->th_seq) + 1;
    
    if (tcp->th_flags == TH_SYN && ti->ti_tcp_state == TCPSTATE_LASTACK) {
        //        tc_finish(ti);
        //        tc_reset(ti);
    }
    
    /* XXX check seq numbers, etc. */
    
    //    check_retransmit(ti, ip, tcp);
    
    if (tcp->th_flags & TH_RST) {
        ti->ti_tcp_state = TCPSTATE_DEAD;
        return result;
    }
    
    return result;
}

static int do_clamp_mss(struct tcpcrypt_info *ti, uint16_t *mss) {
    int len;
    
    len = ntohs(*mss) - ti->ti_mss_clamp;
    assert(len > 0);
    
    *mss = htons(len);
    
    printf("Clamping MSS to %d\n", len);
    
    return NKE_MODIFY;
}

static int clamp_mss(struct ip *ip, struct tcphdr *tcp, struct tcpcrypt_info *ti) {
    struct {
        uint8_t kind;
        uint8_t len;
        uint16_t mss;
    } *mss;
    
    if (ti->ti_mss_clamp == -1)
        return NKE_ACCEPT;
    
    if (!(tcp->th_flags & TH_SYN))
        return NKE_ACCEPT;
    
    if (ti->ti_state == STATE_DISABLED)
        return NKE_ACCEPT;
    
    mss = find_opt(tcp, TCPOPT_MAXSEG);
    if (!mss) {
        mss = tcp_opts_alloc(ti, ip, tcp, sizeof(*mss));
        if (!mss) {
            ti->ti_state = STATE_DISABLED;
            
            printf("Can't clamp MSS\n");
            
            return NKE_ACCEPT;
        }
        
        mss->kind = TCPOPT_MAXSEG;
        mss->len = sizeof(*mss);
        mss->mss = htons(ti->ti_mtu - sizeof(*ip) - sizeof(*tcp));
    }
    
    return do_clamp_mss(ti, &mss->mss);
}

static int negotiate_cipher(struct tcpcrypt_info *ti, struct ti_cipher_spec *a, int an)
{
    printf("negotiate_cipher");
    
    // current ciphers
    struct ti_cipher_spec *b = ti->ti_ciphers_pkey;
    
    // number of ciphers
    int bn = ti->ti_ciphers_pkey_len / sizeof(*ti->ti_ciphers_pkey);
    
    // final cipher
    struct ti_cipher_spec *out = &ti->ti_cipher_pkey;
    
    ti->ti_pub_cipher_list_len = an * sizeof(*a);
    memcpy(ti->ti_pub_cipher_list, a, ti->ti_pub_cipher_list_len);
    
    while (an--) {
        while (bn--) {
            if (a->tcs_algo == b->tcs_algo) {
                out->tcs_algo = a->tcs_algo;
                return 1;
            }
            
            b++;
        }
        
        a++;
    }
    
    return 0;
}

static void init_pkey(struct tcpcrypt_info *ti)
{
    int error;
    
    error = ctl_enqueuedata(ctl_ref, ctl->c_unit, ti, sizeof (ti), 0);
    
    if (error != 0) {
        // probably out socket buffer space
        printf("ctl_enqueuedata failed %d\n", error);
    }
    
    
    
    
    
    lck_mtx_lock(ciphers_mutex);
    
    struct ciphers *c, *c_next;
    struct ti_cipher_spec *s;
    
    assert(tc->tc_cipher_pkey.tcs_algo);
    
    for (c = TAILQ_FIRST(&ciphers_pkey); c != NULL; c = c_next)
    {
        c_next = TAILQ_NEXT(c, c_next);
        
        s = (struct ti_cipher_spec *) c->c_spec;
        
        if (s->tcs_algo == ti->ti_cipher_pkey.tcs_algo) {
            ti->ti_crypt_pub = crypt_new(c->c_cipher->c_ctr);
            return;
        }
    }
    
    lck_mtx_unlock(ciphers_mutex);
    
    assert(!"Can't init cipher");
}

static int tcp_input_post(struct ip *ip, struct tcphdr *tcp,
                          struct tcpcrypt_info *ti)
{
    int result = NKE_ACCEPT;
    
    if (clamp_mss(ip, tcp, ti) == NKE_MODIFY)
        result = NKE_MODIFY;
    
    printf("did clamp MSS\n");
    
    // Make sure kernel doesn't send shit until we connect
    switch (ti->ti_state) {
        case STATE_ENCRYPTING:
        case STATE_REKEY_SENT:
        case STATE_REKEY_RCVD:
        case STATE_DISABLED:
            break;
            
        default:
            tcp->th_win = htons(0);
            result = NKE_MODIFY;
            break;
    }
    
    if (tcp->th_flags & TH_FIN) {
        switch (ti->ti_tcp_state) {
            case TCPSTATE_FIN1_SENT:
                ti->ti_tcp_state = TCPSTATE_FIN2_RCVD;
                break;
                
            case TCPSTATE_LASTACK:
            case TCPSTATE_FIN2_RCVD:
                break;
                
            default:
                ti->ti_tcp_state = TCPSTATE_FIN1_RCVD;
                break;
        }
        
        return result;
    }
    
    if (tcp->th_flags & TH_RST) {
        ti->ti_tcp_state = TCPSTATE_DEAD;
        return result;
    }
    
    switch (ti->ti_tcp_state) {
        case TCPSTATE_FIN2_SENT:
            if (tcp->th_flags & TH_ACK)
                ti->ti_tcp_state = TCPSTATE_DEAD;
            break;
    }
    
    return result;
}

static int opt_input_closed(struct tcpcrypt_info *ti, int tcpop, int len, void *data) {
    uint8_t *p;
    
    printf("opt_input_closed");
    
    if (get_eno(tcpop, &data, &len))
        printf("===> FOUND ENO IN REPLY\n");
    //        input_closed_eno(tc, data, len);
    
    switch (tcpop) {
        case TCPOPT_SACK_PERMITTED:
            p = data;
            p[-2] = TCPOPT_NOP;
            p[-1] = TCPOPT_NOP;
            ti->ti_verdict = NKE_MODIFY;
            break;
            
        case TCPOPT_MAXSEG:
            if (do_clamp_mss(ti, data) == NKE_MODIFY)
                ti->ti_verdict = NKE_MODIFY;
            
            ti->ti_mss_clamp = -1;
            break;
    }
    
    return 0;
}

static int do_input_closed(struct ip *ip, struct tcphdr *tcp, struct tcpcrypt_info *ti) {
    ti->ti_dir = DIRECTION_IN;
    
    if (tcp->th_flags != TH_SYN)
        return NKE_ACCEPT;
    
    ti->ti_verdict = NKE_ACCEPT;
    ti->ti_state = STATE_DISABLED;
    
    foreach_opt(ti, tcp, opt_input_closed);
    
    ti->ti_eno_len = 0;
    set_eno_transcript(ti, tcp);
    
    return ti->ti_verdict;
}

static int do_input_hello_sent(struct ip *ip, struct tcphdr *tcp,
                               struct tcpcrypt_info *ti)
{
    struct ti_cipher_spec *cipher;
    struct tcpopt_eno *eno;
    int len;
    
    if (!(eno = find_eno(tcp))) {
        ti->ti_state = STATE_DISABLED;
        return NKE_ACCEPT;
    }
    
    len = eno->toe_len - sizeof(*eno);
    assert(len >= 0);
    
    //    check_app_support(tc, eno->toe_opts, len);
    
    cipher = (struct ti_cipher_spec *) eno->toe_opts;
    printf("do_input_hello_sent: ");
    
    /* XXX truncate len as it could go to the variable options (like SID) */
    
    if (!negotiate_cipher(ti, cipher, len)) {
        printf("do_input_hello_sent > negotiate_cipher: no cipher\n");
        ti->ti_state = STATE_DISABLED;
        
        return NKE_ACCEPT;
    }
    
    // set_eno_transcript(tc, tcp);
    
    init_pkey(ti);
    
    ti->ti_state = STATE_PKCONF_RCVD;
    
    return NKE_ACCEPT;
}

static int do_input(struct ip *ip, struct tcphdr *tcp, struct tcpcrypt_info *ti)
{
    printf("-----------------------   IN   ---------------------\n");
    
    int result = NKE_DROP;
    int tcp_result, tcp_rc2;
    
    printf("ti->ti_state: %d\n", ti->ti_state);
    
    //    tcp_result = tcp_input_pre(ip, tcp, ti);
    //
    //    /* an RST half way through the handshake */
    //    if (ti->ti_tcp_state == TCPSTATE_DEAD && !connected(ti))
    //        return tcp_result;
    //
    switch (ti->ti_state) {
        case STATE_NEXTK1_RCVD:
            /* XXX check same SID */
        case STATE_HELLO_RCVD:
            //            tc_reset(tc); /* XXX */
        case STATE_CLOSED:
            //            result = do_input_closed(ip, tcp, ti);
            break;
            
        case STATE_HELLO_SENT:
            result = do_input_hello_sent(ip, tcp, ti);
            break;
            
        case STATE_PKCONF_RCVD:
            /* XXX syn ack re-TX check that we're getting the same shit */
            //            assert(tcp->th_flags == (TH_SYN | TH_ACK));
            //            rc = DIVERT_ACCEPT;
            break;
            
        case STATE_NEXTK1_SENT:
            //            rc = do_input_nextk1_sent(tc, ip, tcp);
            break;
            
        case STATE_NEXTK2_SENT:
            //            rc = do_input_nextk2_sent(tc, ip, tcp);
            break;
            
        case STATE_PKCONF_SENT:
            //            rc = do_input_pkconf_sent(tc, ip, tcp);
            break;
            
        case STATE_INIT1_SENT:
            //            rc = do_input_init1_sent(tc, ip, tcp);
            break;
            
        case STATE_INIT2_SENT:
            //            rc = do_input_init2_sent(tc, ip, tcp);
            break;
            
        case STATE_ENCRYPTING:
        case STATE_REKEY_SENT:
        case STATE_REKEY_RCVD:
            //            rc = do_input_encrypting(tc, ip, tcp);
            break;
            
        case STATE_DISABLED:
            //            rc = DIVERT_ACCEPT;
            break;
            
        default:
            printf("Unknown state %d\n", ti->ti_state);
    }
    //
    //    tcp_rc2 = tcp_input_post(ip, tcp, ti);
    //
    //    if (tcp_result == NKE_ACCEPT)
    //        tcp_result = tcp_rc2;
    //
    //    if (result == NKE_ACCEPT)
    //        return tcp_result;
    //
    
    printf("----------------------------------------------------\n");
    return result;
}

static void reinject_packet(mbuf_t *mbuf, unsigned char* packet, size_t length, pkt_dir dir, ipf_pktopts_t options)
{
    int result = KERN_SUCCESS;
    
    // copy buffer back to mbuf
    if (0 != (result = mbuf_copyback(*mbuf, 0, length, packet, M_WAITOK)))
        printf("reinject_packet: 'mbuf_copyback' returned error %d", result);
    
    mbuf_clear_csum_requested(*mbuf);
    
    if (dir)
        result = ipf_inject_output(*mbuf, ip_filter_ref, options);
    else
        result = ipf_inject_input(*mbuf, ip_filter_ref);
    
    if (0 != result)
        mbuf_free(*mbuf);
    
    assert(KERN_SUCCESS == result);
}

/*
 * Handle tcpcrypt packet
 */
static void tcpcrypt_packet(mbuf_t *mbuf, pkt_dir dir, ipf_pktopts_t options)
{
    errno_t result = NKE_MODIFY;
    struct ip *ip;
    struct tcphdr *tcp;
    struct connection *c;
    unsigned char packet[1500];
    mbuf_t old_packet = *mbuf;
    uint32_t packet_bytes = 0;
    
    // zero packet
    bzero((void *) packet, sizeof(packet));
    
    // get length of packet
    do
    {
        packet_bytes += mbuf_len(old_packet);
        old_packet = mbuf_next(old_packet);
    } while (old_packet != NULL);
    
    // "finalize" the packet so that it is safe to modify it
    mbuf_outbound_finalize(*mbuf, AF_INET, 0);
    
    // copy data to local buffer
    if (0 != (result = mbuf_copydata(*mbuf, 0, packet_bytes, packet)))
        printf("ERROR - mbuf_copydata returned %d\n", result);
    
    ip = (struct ip*)packet;
    tcp = (struct tcphdr*)((u_int32_t*)ip + ip->ip_hl);
    
    // TODO: remove
    //    if (tcp->th_flags == (TH_CWR | TH_ECE | TH_SYN))
    //        tcp->th_flags = TH_SYN;
    
    // check if connection has been previously saved
    c = lookup_connection(ip, tcp, dir);
    
    // if not, create and save one
    if (!c)
    {
        printf("INFO - handle_packet, tcpcrypt connection NOT found\n");
        c = new_connection(ip, tcp, dir);
    }
    else
    {
        // DIRECTION_OUT
        if (dir)
        {
            
            //            // discard non SYN packets
            //            // but continue if connection has been already saved but it's
            //            // a SYN packet again, since it's probably a retransmission
            //            if (c->c_ti->ti_state != STATE_DISABLED && !(tcp->th_flags == TH_SYN))
            //            {
            //                printf("INFO - handle_packet, found connection != STATE_DISABLED\n");
            //                return KERN_SUCCESS;
            //            }
            
            //            reinject_packet(mbuf, packet, ntohs(ip->ip_len), dir, options);
            //            goto sent;
        }
        else // DIRECTION_IN
        {
            //            printf("-> state of incoming packet with saved connection: %d\n", c->c_ti->ti_state);
            //            if (c->c_ti->ti_state != STATE_HELLO_SENT)
            //            {
            //                reinject_packet(mbuf, packet, ntohs(ip->ip_len), dir, options);
            //                goto sent;
            //            }
        }
    }
    
    // save direction and init csum
    c->c_ti->ti_dir_packet = dir;
    c->c_ti->ti_csum = 0;
    
    // IN/OUT
    if (dir)
        result = do_output(ip, tcp, c->c_ti);
    else
        result = do_input(ip, tcp, c->c_ti);
    
    // recompute TCP checksum
    if (result == NKE_MODIFY)
        checksum_tcp(ip, tcp);
    
    // handle packet normally
    // TODO: NOT GOOD, do a BACKUP of the original packet, and reinject that one
    //    if (result == NKE_DROP)
    //        reinject_packet(packet, ntohs(ip->ip_len), options);
    
    // if connection has been marked has dead or disabled,
    // then remove connection from saved ones
    //    if (c->c_ti->ti_tcp_state == TCPSTATE_DEAD
    //        || c->c_ti->ti_state == STATE_DISABLED)
    //        remove_connection(ip, tcp, dir);
    
    reinject_packet(mbuf, packet, ntohs(ip->ip_len), dir, options);
    goto sent;
    
sent:
    printf("\n");
}

static int handle_packet(mbuf_t *mbuf, pkt_dir dir, ipf_pktopts_t options)
{
    struct ip *ip;
    struct tcphdr *tcp;
    char dst[32], src[32];
    
    ip = (struct ip*)mbuf_data(*mbuf);
    tcp = (struct tcphdr*)((u_int32_t*)ip + ip->ip_hl);
    
    // filter mbufs with MBUF_PKTHDR flag set and TCP packets
    if (!(mbuf_flags(*mbuf) & MBUF_PKTHDR) || ip->ip_p != IPPROTO_TCP)
        return KERN_SUCCESS;
    
    bzero(dst, sizeof(dst));
    bzero(src, sizeof(src));
    
    // converts the network address structure into a character string
    inet_ntop(AF_INET, &ip->ip_dst, dst, sizeof(dst));
    inet_ntop(AF_INET, &ip->ip_src, src, sizeof(src));
    
    // OUT
    if (dir
        && tcp->th_flags & TH_SYN
        && (strcmp(src, "171.66.3.196") == 0 || strcmp(dst, "171.66.3.196") == 0))
    {
        tcpcrypt_packet(mbuf, DIRECTION_OUT, options);
        return EJUSTRETURN;
    }
    
    // IN
    if (!dir
        /*&& tcp->th_flags == (TH_SYN | TH_ACK)*/
        && (strcmp(src, "171.66.3.196") == 0 || strcmp(dst, "171.66.3.196") == 0))
    {
        tcpcrypt_packet(mbuf, DIRECTION_IN, NULL);
        return EJUSTRETURN;
    }
    
    return KERN_SUCCESS;
}

/**
 Handle outgoing packts
 
 @param cookie The cookie specified when the filter was attached.
 @param data The ip packet, will contain an IP header followed by the rest of the IP packet.
 @param options Options for outgoing packets. The options need to be preserved when re-injecting a packet.
 @return Return:
 0 - The caller will continue with normal processing of the packet.
 EJUSTRETURN - The caller will stop processing the packet, the packet will not be freed.
 Anything Else - The caller will free the packet and stop processing.
 */
errno_t ip_filter_output(void* cookie, mbuf_t *data, ipf_pktopts_t options)
{
    return handle_packet(data, DIRECTION_OUT, options);
}

/**
 Filter ingoing packets
 
 @param cookie The cookie specified when the filter was attached.
 @param data The reassembled ip packet, data will start at the ip header.
 @param offset An offset to the next header.
 @param protocol The protocol type (udp/tcp/icmp/etc...) of the IP packet.
 @return Return:
 0 - The caller will continue with normal processing of the packet.
 EJUSTRETURN - The caller will stop processing the packet, the packet will not be freed.
 Anything Else - The caller will free the packet and stop processing.
 */
errno_t ip_filter_input(void* cookie, mbuf_t* data, int offset, u_int8_t protocol)
{
    return handle_packet(data, DIRECTION_IN, NULL);
}

/**
 Print packets stats when kextunloading the extension
 
 @param cookie The cookie specified when the filter was attached.
 */
void ip_filter_detach(void* cookie)
{
    printf("ip_filter_detach\n");
    
    // free tcpcrypt_info_queue
    free_deferred_data();
    
    ip_filter_detached = TRUE;
}

/**
 Allocate mutex lock used to lock access to the queues.
 When the lock is active, the process has exclusive access to both queues.
 
 1. 'lck_grp_alloc_init' allocates memory for the group lock and inits the lock with the group name and default attributes
 2. 'lck_mtx_alloc_init' allocates the memory for the lock and associates the lock with the specified group
 
 @return 0 on success otherwise the errno error.
 */
static errno_t alloc_locks(void)
{
    errno_t result = 0;
    
    mtx_grp = lck_grp_alloc_init(TCPCRYPT_BUNDLE_ID, LCK_GRP_ATTR_NULL);
    if (mtx_grp == NULL)
    {
        printf("Error calling lck_grp_alloc_init\n");
        result = ENOMEM;
    }
    
    if (result == 0)
    {
        ciphers_list_mutex = lck_mtx_alloc_init(gmutex_grp, LCK_ATTR_NULL);
        if (ciphers_list_mutex == NULL)
        {
            printf("Error calling lck_mtx_alloc_init\n");
            result = ENOMEM;
        }
    }
    
    if (result == 0)
    {
        connections_queue_mtx = lck_mtx_alloc_init(mtx_grp, LCK_ATTR_NULL);
        if (connections_queue_mtx == NULL)
        {
            printf("Error calling lck_mtx_alloc_init\n");
            result = ENOMEM;
        }
    }
    
    return result;
}

/**
 Free locks used to lock access to the queues.
 */
static void free_locks(void)
{
    printf("Freeing locks\n");
    if (gmutex)
    {
        lck_mtx_free(gmutex, gmutex_grp);
        gmutex = NULL;
    }
    
    if (ciphers_list_mutex)
    {
        lck_mtx_free(ciphers_list_mutex, gmutex_grp);
        ciphers_list_mutex = NULL;
    }
    
    if (gmutex_grp)
    {
        lck_grp_free(gmutex_grp);
        gmutex_grp = NULL;
    }
}

static struct ipf_filter ip_filter = {
    NULL,
    TCPCRYPT_BUNDLE_ID,
    ip_filter_input,
    ip_filter_output,
    ip_filter_detach
};

//kern_return_t Kernel_start(kmod_info_t * ki, void *d);
//kern_return_t Kernel_stop(kmod_info_t *ki, void *d);

kern_return_t Kernel_start(kmod_info_t * ki, void *d)
{
    int result;
    
    /*
     * Queues
     */
    TAILQ_INIT(&connections_queue);
    TAILQ_INIT(&ctl_list);
    //TAILQ_INIT(&sessions_queue);
    
    /*
     * Configs
     */
    bzero(&tc_conf, sizeof(struct tc_conf));
    tc_conf.tc_enabled = 1;
    tc_conf.tc_nocache = 0;
    tc_conf.tc_disable_timers = 1;
    
    /*
     * IP filter
     */
    if (KERN_SUCCESS == (result = ipf_addv4(&ip_filter, &ip_filter_ref)))
        ip_filter_registered = TRUE;
    else
    {
        ip_filter_registered = FALSE;
        printf("ERROR - tcpcrypt_start: could not register the ip filter, \
               result %d\n", result);
        goto bail;
    }
    
    /*
     * OSMalloc tag
     */
    malloc_tag = OSMalloc_Tagalloc(TCPCRYPT_BUNDLE_ID, OSMT_DEFAULT);
    if (malloc_tag == NULL)
    {
        IOLog("ERROR - tcpcrypt_start: could not allocate tag\n");
        goto bail;
    }
    
    /*
     * Locks
     */
    result = alloc_locks();
    if (result)
    {
        IOLog("ERROR - tcpcrypt_start: could not allocate locks, result: %d",
              result);
        goto bail;
    }
    
    /*
     * Kernel control
     */
    result = ctl_register(&ctl_reg, &ctl_ref);
    if (result == 0) {
        printf("ctl_register id 0x%x, ref 0x%x \n", ctl_reg.ctl_id, ctl_ref);
        ctl_registered = TRUE;
    }
    else
    {
        printf("ctl_register returned error %d\n", retval);
        goto bail;
    }
    
    return result;
    
bail:
    // detach ip filter
    if (ip_filter_registered)
        ipf_remove(ip_filter_ref);
    
    // free all queues locks
    free_locks();
    
    return KERN_FAILURE;
}

kern_return_t Kernel_stop(kmod_info_t *ki, void *d)
{
    printf("tcpcrypt_stop\n");
    
    int result = KERN_SUCCESS;
    
    if (ip_filter_registered)
    {
        if (0 != (result = ipf_remove(ip_filter_ref)))
        {
            printf("ERROR - ipf_remove failed with error %d\n", result);
            result = KERN_FAILURE;
        }
    }
    
    // deallocate locks and tag
    if (result == KERN_SUCCESS)
    {
        printf("Releasing locks and freeing OSMalloc_tag\n");
        free_locks();
        if (malloc_tag)
        {
            OSMalloc_Tagfree(malloc_tag);
            malloc_tag = NULL;
        }
    }
    
    // deregister kernel control
    if (ctl_registered)
        ctl_deregister(ctl_ref);
    
    // ensure filter is detached before we return
    //    if (!ip_filter_detached)
    //        return EAGAIN; // try unloading again
    
    return result;
}
