//
//  tcpcrypt.h
//  tcpcrypt
//
//  Created by Romeo Bellon on 21/08/2017.
//  Copyright © 2017 Romeo Bellon. All rights reserved.
//

#include <netinet/ip.h>
#include <pthread.h>
#include <sys/queue.h>

#ifndef tcpcrypt_h
#define tcpcrypt_h

#include "crypto.h"
#include "crypto_register.h"
#include "common.h"

// mutex lock for ciphers_list
extern pthread_mutex_t ciphers_list_mutex;

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

// List of ciphers per kind
extern TAILQ_HEAD(ciphers_pkey_head, ciphers) ciphers_pkey;

// List of ciphers per kind
extern TAILQ_HEAD(ciphers_sym_head, ciphers) ciphers_sym;

// List of different ciphers (TC_CIPHER_ECDHE_P256, TC_CIPHER_ECDHE_P521,
// TC_AES128_GCM, TC_AES256_GCM)
extern TAILQ_HEAD(ciphers_list_head, cipher) cipers_list;

#endif /* tcpcrypt_h */
