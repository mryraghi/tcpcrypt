//
//  crypto.h
//  tcpcrypt
//
//  Created by Romeo Bellon.
//  Copyright © 2017 Romeo Bellon. All rights reserved.
//

#ifndef crypto_h
#define crypto_h

#include <sys/types.h>
#include <sys/_types/_iovec_t.h>
#include <sys/queue.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "tcpcrypt.h"

typedef void *(*crypt_ctr)(void);

enum type {
    TYPE_PKEY = 0,
    TYPE_SYM,
};

struct cipher {
    TAILQ_ENTRY(cipher) c_next;
    u_int8_t    c_id;
    int         c_type;
    crypt_ctr   c_ctr;
};

struct ciphers {
    TAILQ_ENTRY(ciphers) c_next;
    struct cipher *c_cipher;
    unsigned char c_spec[4];
    int c_speclen;
};

// low-level interface
// TODO: struct iovec??
struct crypt {
    void	*c_priv;
    void	(*c_destroy)(struct crypt *c);
    int     (*c_set_key)(struct crypt *c, void *key, int len);
    int     (*c_get_key)(struct crypt *c, void **out);
    void	(*c_mac)(struct crypt *, const struct iovec *iov, int num,
                     void *out, int *outlen);
    void	(*c_extract)(struct crypt *c, struct iovec *iov, int num, void *out,
                         int *outlen);
    void	(*c_expand)(struct crypt *c, void *tag, int taglen, void *out,
                        int outlen);
    int     (*c_encrypt)(struct crypt *c, void *iv, void *data, int len);
    int     (*c_decrypt)(struct crypt *c, void *iv, void *data, int len);
    int     (*c_aead_encrypt)(struct crypt *c, void *iv, void *aad, int aadlen,
                              void *data, int dlen, void *tag);
    int     (*c_aead_decrypt)(struct crypt *c, void *iv, void *aad, int aadlen,
                              void *data, int dlen, void *tag);
    int     (*c_compute_key)(struct crypt *c, void *out);
};

// pub crypto
struct crypt_pub {
    crypt_ctr    cp_ctr;		/* must be first */
    struct crypt *cp_hkdf;
    struct crypt *cp_pub;
    int	     cp_n_c;
    int	     cp_n_s;
    int	     cp_k_len;
    int	     cp_min_key;
    int	     cp_max_key;
    int	     cp_cipher_len;
    int	     cp_key_agreement;
};

// sym crypto
struct crypt_sym {
    crypt_ctr	cs_ctr;		/* must be first */
    struct crypt	*cs_cipher;
    struct crypt	*cs_mac;
    struct crypt	*cs_ack_mac;
    int		cs_mac_len;
    int		cs_key_len;
    int		cs_iv_len;
};

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
    free(cp);
}

static inline void crypt_sym_destroy(struct crypt_sym *cs) {
    crypt_destroy(cs->cs_cipher);
    crypt_destroy(cs->cs_mac);
    crypt_destroy(cs->cs_ack_mac);
    free(cs);
}

extern struct crypt *crypt_HMAC_SHA256_new(void); // crypto_hmac.c
extern struct crypt *crypt_HKDF_SHA256_new(void); // crypto_hkdf.c
extern struct crypt *crypt_ECDHE256_new(void); // crypto_ecdhe.c
extern struct crypt *crypt_ECDHE521_new(void); // crypto_ecdhe.c
extern struct crypt *crypt_AES128_new(void); // crypto_aes.c
extern struct crypt *crypt_AES256_new(void); // crypto_aes.c

extern void crypt_register(int type, uint8_t id, crypt_ctr ctr);
extern struct crypt *crypt_init(int sz);

extern void do_add_ciphers(void *c_l, enum type type, void *spec, int *speclen, int sz, void *specend);
extern void setup_ciphers(void);
extern void init_ciphers(void *c_l, enum type type);

#endif /* crypto_h */
