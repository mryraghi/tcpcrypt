//
//  crypto.c
//  tcpcrypt
//
//  Created by Romeo Bellon.
//  Copyright © 2017 Romeo Bellon. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"

// List of different ciphers (TC_CIPHER_ECDHE_P256, TC_CIPHER_ECDHE_P521,
// TC_AES128_GCM, TC_AES256_GCM)
static struct cipher _ciphers;

struct cipher *get_ciphers(void)
{
    return _ciphers.c_next;
}

void do_add_ciphers(struct ciphers *c, void *spec, int *speclen, int sz, void *specend)
{
    printf("do_add_ciphers\n");
    
    uint8_t *p = (uint8_t *) spec + *speclen;
    
    c = c->c_next;
    
    while (c) {
        unsigned char *sp = c->c_spec;
        
        assert(p + sz <= (uint8_t *) specend);
        
        memcpy(p, sp, sz);
        p += sz;
        *speclen += sz;
        
        c = c->c_next;
    }
}

void init_cipher(struct ciphers *c)
{
    if (!c->c_cipher)
        c = c->c_next;
    
    printf("init_cipher\n");
    
    struct crypt_pub *cp;
    struct crypt_sym *cs;
    uint8_t spec = c->c_cipher->c_id;
    
    printf("\tspec 0x%x, type %d\n", spec, c->c_cipher->c_type);
    
    switch (c->c_cipher->c_type) {
        case TYPE_PKEY:
            c->c_speclen = 1;
            
            cp = c->c_cipher->c_ctr();
            crypt_pub_destroy(cp);
            break;
            
        case TYPE_SYM:
            c->c_speclen = 1;
            
            cs = crypt_new(c->c_cipher->c_ctr);
            crypt_sym_destroy(cs);
            break;
            
        default:
            assert(!"unknown type");
            abort();
    }
    
    memcpy(c->c_spec,
           ((unsigned char *) &spec) + sizeof(spec) - c->c_speclen,
           c->c_speclen);
}

struct crypt *crypt_init(int sz)
{
    struct crypt *c = malloc(sizeof(*c));
    bzero(c, sizeof(*c));
    
    if (sz) {
        c->c_priv = malloc(sz);
        bzero(c->c_priv, sz);
    }
    
    return c;
}

/**
 Adds a supported ciphers to the ciphers list for future usage.

 @param type TYPE_PKEY,
             TYPE_SYM
 
 @param id   TC_CIPHER_ECDHE_P256,
             TC_CIPHER_ECDHE_P521,
             TC_AES128_GCM,
             TC_AES256_GCM
 
 @param ctr  ECDHE256_HKDF_new,
             ECDHE521_HKDF_new,
             AES128_GCM_new,
             AES256_GCM_new
 */
void crypt_register(int type, uint8_t id, crypt_ctr ctr)
{
    struct cipher *c = malloc(sizeof(*c));
    bzero(c, sizeof(*c));

    c->c_type   = type;
    c->c_id     = id;
    c->c_ctr    = ctr;
    c->c_next   = _ciphers.c_next;
    _ciphers.c_next = c;
    
    printf("crypto: registered 0x%x\n", id);
}
