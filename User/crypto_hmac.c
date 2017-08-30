//
//  crypto_hmac.c
//  tcpcrypt
//
//  Created by Romeo Bellon.
//  Copyright © 2017 Romeo Bellon. All rights reserved.
//

#include <openssl/hmac.h>

#include "crypto.h"

#define MAC_SIZE 32

struct hmac_priv {
    HMAC_CTX    *hp_ctx;
    int         hp_fresh;
};

static void hmac_destroy(struct crypt *c)
{
    struct hmac_priv *hp = crypt_priv(c);
    
    if (!hp)
        printf("hmac_destroy: null priv");
    
    /*
     * Erases the key and other data from the HMAC_CTX, releases
     * any associated resources and finally frees the HMAC_CTX itself.
     */
    HMAC_CTX_free(hp->hp_ctx);
    
    free(hp);
    free(c);
}

static int hmac_set_key(struct crypt *c, void *key, int len)
{
    struct hmac_priv *hp = crypt_priv(c);
    
    if (HMAC_Init_ex(hp->hp_ctx, key, len, NULL, NULL) != 1)
        printf("HMAC_Init_ex: error");
    
    hp->hp_fresh = 1;
    
    return 0;
}

static void hmac_mac(struct crypt *c, const struct iovec *iov, int num,
                     void *out, int *outlen)
{
    struct hmac_priv *hp = crypt_priv(c);
    void *o = out;
    unsigned int olen = MAC_SIZE;
    
    printf("hmac_mac: in");
    
    if (!hp->hp_fresh) {
        if (HMAC_Init_ex(hp->hp_ctx, NULL, 0, NULL, NULL) != 1)
            printf("HMAC_Init_ex: error");
    }
    else
        hp->hp_fresh = 0;
    
    while (num--) {
        if (HMAC_Update(hp->hp_ctx, iov->iov_base, iov->iov_len) != 1)
            printf("HMAC_Update: error");
        
        printf("hmac_mac: update");
        
        iov++;
    }
    
    if (*outlen < MAC_SIZE)
        o = malloc(MAC_SIZE);
    
    if (HMAC_Final(hp->hp_ctx, o, &olen) != 1)
        printf("HMAC_Final: error");
    
    printf("hmac_mac: final");
    
    if (*outlen < MAC_SIZE)
        memcpy(out, o, *outlen);
    else
        *outlen = olen;
    
    free(o);
}

struct crypt *crypt_HMAC_SHA256_new(void)
{
    struct hmac_priv *hp;
    struct crypt *c;
    
    c = crypt_init(sizeof(*hp));
    c->c_destroy = hmac_destroy;
    c->c_set_key = hmac_set_key;
    c->c_mac     = hmac_mac;
    
    hp = crypt_priv(c);
    
    hp->hp_ctx = HMAC_CTX_new();
    if (!hp->hp_ctx)
        printf("HMAC_CTX_new: error");
    
    if (HMAC_Init_ex(hp->hp_ctx, "a", 1, EVP_sha256(), NULL) != 1)
        printf("HMAC_Init_ex: error");
    
    return c;
}
