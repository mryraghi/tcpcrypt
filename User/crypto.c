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

pthread_mutex_t ciphers_list_mutex;

void do_add_ciphers(void *c_l, enum type type, void *spec, int *speclen, int sz, void *specend)
{
    uint8_t *p = (uint8_t *) spec + *speclen;
    
    pthread_mutex_lock(&ciphers_list_mutex);
    
    struct ciphers *c, *c_next, *c_tmp;
    
    if (type == TYPE_PKEY)
        c_tmp = TAILQ_FIRST((struct ciphers_pkey_head *) c_l);
    else
        c_tmp = TAILQ_FIRST((struct ciphers_sym_head *) c_l);
    
    for (c = c_tmp; c != NULL; c = c_next)
    {
        c_next = TAILQ_NEXT(c, c_next);
        
        unsigned char *sp = c->c_spec;
        
        assert(p + sz <= (uint8_t *) specend);
        
        memcpy(p, sp, sz);
        p += sz;
        *speclen += sz;
    }
    
    pthread_mutex_unlock(&ciphers_list_mutex);
}

void setup_ciphers()
{
    pthread_mutex_lock(&ciphers_list_mutex);
    
    struct cipher *c, *c_next;
    struct ciphers_list_head ciphers_list;
    struct ciphers_pkey_head ciphers_pkey;
    struct ciphers_sym_head ciphers_sym;
    
    for (c = TAILQ_FIRST(&ciphers_list); c != NULL; c = c_next)
    {
        c_next = TAILQ_NEXT(c, c_next);
        
        struct ciphers *x = malloc(sizeof(*x));
        bzero(x, sizeof(*x));
        x->c_cipher = c;
        
        int type = c->c_type;
        
        switch (type) {
            case TYPE_PKEY:
                TAILQ_INSERT_TAIL(&ciphers_pkey, x, c_next);
                break;
                
            case TYPE_SYM:
                TAILQ_INSERT_TAIL(&ciphers_sym, x, c_next);
                break;
                
            default:
                assert(!"Unknown type");
                break;
        }
    }
    
    pthread_mutex_unlock(&ciphers_list_mutex);
}

void init_ciphers(void *c_l, enum type type)
{
    pthread_mutex_lock(&ciphers_list_mutex);
    
    struct ciphers *c, *c_next, *c_tmp;
    
    if (type == TYPE_PKEY)
        c_tmp = TAILQ_FIRST((struct ciphers_pkey_head *) c_l);
    else
        c_tmp = TAILQ_FIRST((struct ciphers_sym_head *) c_l);
    
    for (c = c_tmp; c != NULL; c = c_next)
    {
        c_next = TAILQ_NEXT(c, c_next);
        
        struct crypt_pub *cp;
        struct crypt_sym *cs;
        uint8_t spec = c->c_cipher->c_id;
        
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
    
    pthread_mutex_unlock(&ciphers_list_mutex);
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
    struct ciphers_list_head ciphers_list;
    struct cipher *c = malloc(sizeof(*c));
    bzero(c, sizeof(*c));

    c->c_type   = type;
    c->c_id     = id;
    c->c_ctr    = ctr;
    
    pthread_mutex_t ciphers_list_mutex;
    
    pthread_mutex_lock(&ciphers_list_mutex);
    
    TAILQ_INSERT_HEAD(&ciphers_list, c, c_next);
    
    pthread_mutex_unlock(&ciphers_list_mutex);
}
