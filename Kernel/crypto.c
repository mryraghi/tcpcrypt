//
//  crypto.c
//  tcpcrypt
//
//  Created by Romeo Bellon on 23/07/2017.
//  Copyright © 2017 Romeo Bellon. All rights reserved.
//

#include "crypto.h"

/*
 * Functions common to every cipher
 */

static inline void *crypt_priv(struct crypt *c)
{
    return c->c_priv;
}

static inline void crypt_destroy(struct crypt *c)
{
    c->c_destroy(c);
}

static inline int crypt_get_key(struct crypt *c, void **out)
{
    return c->c_get_key(c, out);
}

static inline int crypt_set_key(struct crypt *c, void *key, int len)
{
    return c->c_set_key(c, key, len);
}

static inline void crypt_mac(struct crypt *c, struct iovec *iov, int num,
                             void *out, int *outlen)
{
    c->c_mac(c, iov, num, out, outlen);
}

static inline void *crypt_new(crypt_ctr ctr)
{
    crypt_ctr *r = ctr();
    
    *r = ctr;
    
    return r;
}

static inline void crypt_pub_destroy(struct crypt_pub *cp) {
    crypt_destroy(cp->cp_hkdf);
    crypt_destroy(cp->cp_pub);
    
    OSFree(cp, sizeof(*cp), malloc_tag);
}

static inline void crypt_sym_destroy(struct crypt_sym *cs) {
    crypt_destroy(cs->cs_cipher);
    crypt_destroy(cs->cs_mac);
    crypt_destroy(cs->cs_ack_mac);

    OSFree(cs, sizeof(*cs), malloc_tag);
}
