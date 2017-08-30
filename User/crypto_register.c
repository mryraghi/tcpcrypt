//
//  crypto_register.c
//  tcpcrypt
//
//  Created by Romeo Bellon.
//  Copyright © 2017 Romeo Bellon. All rights reserved.
//

#include "crypto_register.h"

static struct crypt_pub *ECDHE_HKDF_new(struct crypt*(*ctr)(void), int klen)
{
    struct crypt_pub *cp = malloc(sizeof(*cp));
    bzero(cp, sizeof(*cp));
    
    cp->cp_hkdf          = crypt_HKDF_SHA256_new();
    cp->cp_pub           = ctr();
    cp->cp_n_c           = 32;
    cp->cp_n_s           = 32;
    cp->cp_k_len         = 32;
    cp->cp_max_key       = (4096 / 8);
    cp->cp_cipher_len    = cp->cp_n_s + klen;
    cp->cp_key_agreement = 1;
    
    return cp;
}

static struct crypt_pub *ECDHE256_HKDF_new(void)
{
    return ECDHE_HKDF_new(crypt_ECDHE256_new, 65 + 2);
}

static struct crypt_pub *ECDHE521_HKDF_new(void)
{
    return ECDHE_HKDF_new(crypt_ECDHE521_new, 133 + 2);
}

static struct crypt_sym *AES_GCM_new(struct crypt*(*ctr)(void), int mlen,
                                     int klen)
{
    struct crypt_sym *cs = malloc(sizeof(*cs));
    bzero(cs, sizeof(*cs));
    
    cs->cs_cipher  = ctr();
    cs->cs_mac     = ctr();
    cs->cs_ack_mac = ctr();
    cs->cs_mac_len = mlen;
    cs->cs_key_len = klen;
    
    return cs;
}

static struct crypt_sym *AES128_GCM_new(void)
{
    return AES_GCM_new(crypt_AES128_new, 16, 128 / 8);
}

static struct crypt_sym *AES256_GCM_new(void)
{
    return AES_GCM_new(crypt_AES256_new, 16, 256 / 8);
}

static void register_pub(uint8_t id, struct crypt_pub *(*ctr)(void))
{
    crypt_register(TYPE_PKEY, id, (crypt_ctr) ctr);
}

static void register_sym(uint8_t id, struct crypt_sym *(*ctr)(void))
{
    crypt_register(TYPE_SYM, id, (crypt_ctr) ctr);
}

void register_ciphers(void)
{
    register_pub(TC_CIPHER_ECDHE_P256, ECDHE256_HKDF_new);
    register_pub(TC_CIPHER_ECDHE_P521, ECDHE521_HKDF_new);
    
    register_sym(TC_AES128_GCM, AES128_GCM_new);
    register_sym(TC_AES256_GCM, AES256_GCM_new);
}
