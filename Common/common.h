//
//  common.h
//  Kernel
//
//  Created by Romeo Bellon.
//  Copyright © 2017 Romeo Bellon. All rights reserved.
//

#ifndef common_h
#define common_h

#define TCPCRYPT_BUNDLE_ID "com.tcpcrypt"
#define TCPCRYPT_MAX_PRF 32
#define CTL_SEND_BUFFER_SIZE (8 * 1024)
#define CTL_RCV_BUFFER_SIZE (8 * 1024)
#define MAX_NONCE 48
#define MAX_CIPHERS 8
#define MAX_SS  32

enum {
    TCPCRYPT_PKEY   = 0,
    TCPCRYPT_SYMMETRIC,
    TCPCRYPT_MAC,
    TCPCRYPT_SYMMETRIC2,
    TCPCRYPT_MAC2,
    
    TCPCRYPT_CRYPT_MAX
};

struct ti_cipher_spec {
    uint8_t  tcs_algo;
} __attribute__ ((__packed__));

struct ti_scipher {
    uint8_t sc_algo;
};

struct stuff {
    uint8_t    s_data[MAX_SS * 2];
    int    s_len;
};

struct ti_keys {
    struct stuff    tk_prk;
};

struct ti_keyset {
    struct ti_keys      ti_client;
    struct ti_keys      ti_server;
    struct crypt_sym    *ti_alg_tx;
    struct crypt_sym    *ti_alg_rx;
};

struct tcpcrypt_info {
    int ti_state;
    int ti_tcp_state;
    
    struct in_addr ti_dst_ip;
    int ti_dst_port;
    
    int ti_opt_len; // tcp option length
    unsigned char   ti_eno[1500];
    int ti_eno_len; // tcp eno option length
    
    unsigned char   ti_hashbuf[1500];
    int ti_hashbuf_len;
    unsigned char   *ti_hashbuf_sym;
    unsigned char   ti_crap[1500];
    int ti_role;
    
    struct tcpcrypt_cache   *ti_cached;
    int ti_support;
    uint32_t    ti_magic; // used to ensure that the system passes our buffer
    
    struct connection *ti_conn;
    int ti_app_support;
    uint64_t ti_isn;
    uint64_t ti_isn_peer;
    unsigned char ti_init1[1500];
    int ti_init1_len;
    int ti_mtu;
    int ti_mss_clamp;
    int ti_seq_off;
    int ti_sack_disable;
    
    uint8_t ti_nonce[MAX_NONCE];
    int ti_nonce_len;
    
    int ti_rto;
    int ti_dir;
    int ti_nocache;
    int ti_dir_packet;
    int ti_csum;
    int ti_verdict;
    struct retransmit *ti_retransmit;
    void *ti_last_ack_timer;
    struct ti_sess *ti_sess;
    struct tcpcrypt_info *ti_rdr_peer;
    
    struct ti_cipher_spec *ti_ciphers_pkey;
    int ti_ciphers_pkey_len;
    struct ti_cipher_spec ti_cipher_pkey;
    struct ti_scipher *ti_ciphers_sym;
    int ti_ciphers_sym_len;
    struct crypt_pub *ti_crypt_pub;
    struct crypt_sym *ti_crypt_sym;
    struct stuff ti_sid;
    struct ti_keyset ti_key_current;
    struct ti_keyset ti_key_next;
    
    struct ti_cipher_spec ti_pub_cipher_list[MAX_CIPHERS];
    int ti_pub_cipher_list_len;
    struct ti_scipher ti_sym_cipher_list[MAX_CIPHERS];
    int ti_sym_cipher_list_len;
    
    // ctl
    int ti_ciphers_init;
} __attribute__ ((packed));

enum ctl_action {
    INIT_TI,
    INIT_PKEY
};

struct ctl_data {
    enum ctl_action c_action;
    struct tcpcrypt_info c_ti;
} __attribute__ ((packed));

#endif /* common_h */
