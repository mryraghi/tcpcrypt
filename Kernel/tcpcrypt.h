//
//  tcpcrypt.h
//  Tcpcrypt
//
//  Created by Romeo Bellon.
//  Copyright © 2017 Romeo Bellon. All rights reserved.
//

#include <netinet/kpi_ipfilter.h>
#include <libkern/libkern.h> // printf
#include <libkern/OSMalloc.h>
#include <string.h>
#include <kern/assert.h>
#include <mach/mach_types.h>
#include <sys/kernel_types.h>
#include <sys/kpi_mbuf.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/systm.h>
#include <sys/kern_control.h>

#ifndef tcpcrypt_h
#define tcpcrypt_h

#include "crypto.h"
#include "checksum.h"
#include "ctl.h"
#include "common.h"

#define TCPCRYPT_TAG_TYPE   1
#define TCPOPT_EXP  253
#define EXID_ENO    0x454E
#define TC_MTU  1500 // 1500 max allowed by Ethernet at the network layer

// mutex locks
extern lck_mtx_t *ciphers_list_mutex;
lck_mtx_t *ciphers_mutex;
lck_mtx_t *connections_queue_mtx;
lck_grp_t *mtx_grp;

extern lck_mtx_t *ctl_list_mutex;

// PKEY
enum {
    TC_CIPHER_ECDHE_P256 = 0x21,
    TC_CIPHER_ECDHE_P521 = 0x22,
};

// SYM
enum {
    TC_AES128_GCM = 0x01,
    TC_AES256_GCM = 0x02,
};

/*
 * ENO
 */

struct tcpopt_eno {
    uint8_t     toe_kind; // SYN: 253
    uint8_t     toe_len;
    uint16_t    toe_exid; // SYN: 0x454E
    uint8_t     toe_opts[0];
} __attribute__ ((__packed__));

/*
 * Values to use with the memory allocated by the tag function,
 * to indicate which processing has been performed already.
 */
typedef enum MBUF_PROC_FLAGS    {
    INBOUND_DONE = 1,
    OUTBOUND_DONE
} MBUF_PROC_FLAGS;

/*
 * Packet direction in IP filter
 */
enum {
    DIRECTION_IN    = 0,
    DIRECTION_OUT    = 1
};
typedef u_int32_t pkt_dir;

enum {
    NKE_ACCEPT = 0, // reinject the original packet
    NKE_DROP, // drop the packet
    NKE_MODIFY, // reinject the modified packet
};

struct tc_conf {
    int tc_enabled;
    int tc_nocache;
    int tc_disable_timers;
};

enum {
    STATE_CLOSED        =  0,
    STATE_HELLO_SENT,
    STATE_HELLO_RCVD,
    STATE_PKCONF_SENT,
    STATE_PKCONF_RCVD,
    STATE_INIT1_SENT    =  5,
    STATE_INIT1_RCVD,
    STATE_INIT2_SENT,
    STATE_ENCRYPTING,
    STATE_DISABLED,
    STATE_NEXTK1_SENT    = 10,
    STATE_NEXTK1_RCVD,
    STATE_NEXTK2_SENT,
    STATE_REKEY_SENT,
    STATE_REKEY_RCVD,
    STATE_RDR_PLAIN        = 15,
};

enum {
    ROLE_CLIENT = 1,
    ROLE_SERVER,
};

enum {
    TCPSTATE_CLOSED    = 0,
    TCPSTATE_FIN1_SENT,
    TCPSTATE_FIN1_RCVD,
    TCPSTATE_FIN2_SENT,
    TCPSTATE_FIN2_RCVD,
    TCPSTATE_LASTACK,
    TCPSTATE_DEAD,
};

enum {
    TCPCRYPT_CLOSED         =  0,
    TCPCRYPT_HELLO_SENT,
    TCPCRYPT_PKCONF_RCVD,
    TCPCRYPT_INIT1_SENT,
    
    TCPCRYPT_LISTEN,
    TCPCRYPT_PKCONF_SENT    =  5,
    TCPCRYPT_INIT1_RCVD,
    
    TCPCRYPT_NEXTK1_SENT,
    TCPCRYPT_NEXTK2_SENT,
    
    TCPCRYPT_ENCRYPTING,
    TCPCRYPT_DISABLED       = 10,
};

enum {
    TCPCRYPT_ECDHE_P256 = 0x21,
    TCPCRYPT_ECDHE_P512 = 0X22,
    TCPCRYPT_ECDHE_Curve25519 = 0x23,
    TCPCRYPT_ECDHE_Curve448 = 0x24,
    TCP_Use_TLS = 0x30
};

/*
 * 3.3 Key exchange
 */

enum {
    CONST_NEXTK     = 0x01,
    CONST_SESSID    = 0x02,
    CONST_REKEY     = 0x03,
    CONST_KEY_C     = 0x04,
    CONST_KEY_S     = 0x05,
    CONST_KEY_ENC   = 0x06,
    
    CONST_KEY_MAC   = 0x07,
    CONST_KEY_ACK   = 0x08
};

enum {
    TC_INIT1 = 0x15101a0e,
    TC_INIT2 = 0x097105e0,
};

struct tc_init1 {
    uint32_t    i1_magic;
    uint32_t    i1_len;
    uint8_t     i1_nciphers;
    uint8_t     i1_data[0];
} __attribute__ ((__packed__));

struct ti_sid {
    uint8_t ts_sid[10];
} __attribute__ ((__packed__));

struct crypt_alg {
    struct crypt_ops    *ca_ops;
    void    *ca_priv;
};

/**
 Session struct
 */
struct ti_sess {
    TAILQ_ENTRY(ti_sess) ts_next;
    struct crypt_pub    *ts_pub;
    struct crypt_sym    *ts_sym;
    struct crypt_alg    ts_mac;
    struct stuff        ts_sid;
    struct stuff        ts_nk;
    struct stuff        ts_mk;
    uint8_t        ts_pub_spec;
    int            ts_role;
    struct in_addr        ts_ip;
    int            ts_port;
    int            ts_dir; // direction
    int            ts_used; // session used: when STATE_NEXTK1_SENT then ts_used = 1
};

struct connection {
    struct sockaddr_in c_addr[2];
    struct tcpcrypt_info *c_ti;
    TAILQ_ENTRY(connection) c_next;
};

// Tag for use with OSMalloc calls, used to associate memory allocations
extern OSMallocTag malloc_tag;

extern TAILQ_HEAD(, connection) connections_queue;

#endif /* tcpcrypt_h */
