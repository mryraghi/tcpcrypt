//
//  crypto_ecdhe.c
//  tcpcrypt
//
//  Created by Romeo Bellon on 31/07/2017.
//  Copyright © 2017 Romeo Bellon. All rights reserved.
//

#include <openssl/evp.h>
#include <openssl/ec.h>

#include "crypto.h"

struct ecdhe_priv {
    EC_KEY  *ec_key;
    EC_KEY  *ec_peer;
    void    *ec_bin;
    int     ec_bin_len;
    int     ec_nid;
};

static int set_peer_key(struct crypt *c, void *key, int len)
{
    struct ecdhe_priv *p = crypt_priv(c);
    EC_KEY *k;
    uint16_t *klen = key;
    const unsigned char *kk = (unsigned char*) (klen + 1);
    
    if (len < sizeof(*klen))
        return -1;
    
    if (ntohs(*klen) != len)
        return -1;
    
    len -= sizeof(*klen);
    
    k = EC_KEY_new_by_curve_name(p->ec_nid);
    assert(k);
    
    k = o2i_ECPublicKey(&k, &kk, len);
    if (!k)
        return -1;
    
    p->ec_peer = k;
    
    return 0;
}

static void ecdhe_destroy(struct crypt *c)
{
    struct ecdhe_priv *tp = crypt_priv(c);
    
    if (!tp)
        return;
    
    if (tp->ec_key)
        EC_KEY_free(tp->ec_key);
    
    if (tp->ec_peer)
        EC_KEY_free(tp->ec_peer);
    
    if (tp->ec_bin)
        free(tp->ec_bin);
    
    free(tp);
    free(c);
}

static int ecdhe_get_key(struct crypt *c, void **out)
{
    struct ecdhe_priv *p = crypt_priv(c);
    
    *out = p->ec_bin;
    
    return p->ec_bin_len;
}

static int ecdhe_set_key(struct crypt *c, void *key, int len)
{
    return set_peer_key(c, key, len);
}

static int ecdhe_compute_key(struct crypt *c, void *out)
{
    struct ecdhe_priv *ec = crypt_priv(c);
    
    return ECDH_compute_key(out, 1024,
                            EC_KEY_get0_public_key(ec->ec_peer),
                            ec->ec_key, NULL);
}

static int ecdhe_encrypt(struct crypt *c, void *iv, void *data, int len)
{
    struct ecdhe_priv *tp = crypt_priv(c);
    unsigned char *p = data;
    
    p += len;
    
    memcpy(p, tp->ec_bin, tp->ec_bin_len);
    
    p += tp->ec_bin_len;
    
    return (unsigned long) p - (unsigned long) data;
}

static int ecdhe_decrypt(struct crypt *c, void *iv, void *data, int len)
{
    unsigned char *p = data;
    int nonce_len = 32;
    
    p += nonce_len;
    
    len -= (unsigned long) p - (unsigned long) data;
    if (len <= 0)
        return -1;
    
    if (set_peer_key(c, p, len) == -1)
        return -1;
    
    return ecdhe_compute_key(c, data);
}

static struct crypt *crypt_ECDHE_new(int nid)
{
    struct ecdhe_priv *r;
    struct crypt *c;
    unsigned char *p;
    uint16_t *len;
    
    c = crypt_init(sizeof(*r));
    c->c_destroy     = ecdhe_destroy;
    c->c_get_key     = ecdhe_get_key;
    c->c_set_key     = ecdhe_set_key;
    c->c_encrypt     = ecdhe_encrypt;
    c->c_decrypt     = ecdhe_decrypt;
    c->c_compute_key = ecdhe_compute_key;
    
    r = crypt_priv(c);
    
    r->ec_nid = nid;
    
    if (!(r->ec_key = EC_KEY_new_by_curve_name(r->ec_nid)))
        printf("crypt_ECDHE_new: unknown curve nid %d", nid);
    
    if (EC_KEY_generate_key(r->ec_key) != 1)
        printf("EC_KEY_generate_key: error");
    
    r->ec_bin_len = i2o_ECPublicKey(r->ec_key, NULL);
    assert(r->ec_bin_len > 0);
    
    /* prefix it with length */
    r->ec_bin_len += sizeof(*len);
    len = r->ec_bin = malloc(r->ec_bin_len);
    
    *len++ = htons(r->ec_bin_len);
    
    p = (unsigned char*) len;
    i2o_ECPublicKey(r->ec_key, &p);
    
    return c;
}

struct crypt *crypt_ECDHE256_new(void)
{
    return crypt_ECDHE_new(NID_X9_62_prime256v1);
}

struct crypt *crypt_ECDHE521_new(void)
{
    return crypt_ECDHE_new(NID_secp521r1);
}
