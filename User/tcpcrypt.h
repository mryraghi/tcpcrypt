//
//  tcpcrypt.h
//  tcpcrypt
//
//  Created by Romeo Bellon.
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

#endif /* tcpcrypt_h */
