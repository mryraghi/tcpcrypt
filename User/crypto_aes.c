//
//  crypto_aes.c
//  tcpcrypt
//
//  Created by Romeo Bellon on 31/07/2017.
//  Copyright © 2017 Romeo Bellon. All rights reserved.
//

#include <openssl/evp.h>

#include "crypto.h"

#define BLEN 16

struct aes_priv {
    EVP_CIPHER_CTX  *ap_ctx;
    uint8_t         ap_key[1024];
    int             ap_key_len;
};

static void aes_destroy(struct crypt *c)
{
    struct aes_priv *p = crypt_priv(c);
    
    EVP_CIPHER_CTX_free(p->ap_ctx);
    
    free(p);
    free(c);
}

static int aes_set_key(struct crypt *c, void *key, int len)
{
    struct aes_priv *ap = crypt_priv(c);
    
    assert(len <= sizeof(ap->ap_key));
    
    memcpy(ap->ap_key, key, len);
    ap->ap_key_len = len;
    
    return 0;
}

static void aes_ack_mac(struct crypt *c, const struct iovec *iov, int num, void *out,
                        int *outlen)
{
    struct aes_priv *ap = crypt_priv(c);
    unsigned char block[BLEN];
    
    assert(num == 1);
    assert(iov->iov_len <= sizeof(block));
    
    bzero(block, sizeof(block));
    memcpy(block, iov->iov_base, iov->iov_len);
    
    if (!EVP_EncryptUpdate(ap->ap_ctx, out, outlen, block, sizeof(block)))
        printf("EVP_EncryptUpdate: error");
}

static void do_aes(struct crypt *c, void *iv, void *data, int len, int enc)
{
    struct aes_priv *ap = crypt_priv(c);
    int blen;
    uint8_t *blocks;
    uint64_t ctr;
    uint64_t inc = ntohl(1);
    int rem, drem;
    uint64_t *ctrp;
    int i;
    uint32_t *pb, *pd;
    uint8_t *pb2, *pd2;
    uint16_t* csum = data;
    
    printf("do_aes: in");
    assert(len);
    
    // figure out counter value and remainder (use of previous block)
    ctr  = ntohl(*((uint64_t*) iv)); // TODO
    rem  = ctr & 0xf;
    ctr &= ~0xf;
    //xhtobe64(ctr);
    
    // figure out how many blocks we need
    blen = (len & ~0xf);
    if (rem)
        blen += BLEN;
    
    drem = len & 0xf;
    if (drem && ((drem > (16 - rem)) || !rem))
        blen += BLEN;
    
    blocks = malloc(blen);
    
    assert(blocks);
    
    printf("do_aes: setup");
    
    // fill blocks with counter values
    ctrp = (uint64_t*) blocks;
    for (i = 0; i < (blen >> 4); i++) {
        *ctrp++ = 0;
        *ctrp++ = ctr;
        ctr    += inc;
    }
    
    printf("do_aes: fill blocks");
    
    // do AES
    i = blen;
    if (!EVP_EncryptUpdate(ap->ap_ctx, blocks, &i, blocks, blen))
        printf("EVP_EncryptUpdate: error");
    
    assert(i == blen);
    
    printf("do_aes: AES");
    
    // XOR data (and checksum)
    pb = (uint32_t*) &blocks[rem];
    pd = (uint32_t*) data;
    while (len >= 4) {
        *pd++ ^= *pb++;
        len   -= 4;
        
        // tc->tc_csum += *csum++;
        // tc->tc_csum += *csum++;
    }
    
    printf("do_aes: XOR words");
    
    // XOR any remainder (< 4 bytes)
    i   = 0; // unsummed
    pb2 = (uint8_t*) pb;
    pd2 = (uint8_t*) pd;
    while (len > 0) {
        *pd2++ ^= *pb2++;
        len--;
        
        if (i == 1) {
            // tc->tc_csum += *csum++;
            i = 0;
        } else
            i++;
    }
    
    printf("do_aes: XOR remainder");
    
    assert(pb2 - blocks <= blen);
    assert(blen - (pb2 - blocks) < 16); // efficiency
    
    // sum odd byte
    if (i) {
        i = 0;
        *((uint8_t*) &i) = *((uint8_t*) csum);
        // tc->tc_csum += i;
    }
    
    free(blocks);
}

static int aes_encrypt(struct crypt *c, void *iv, void *data, int len)
{
    do_aes(c, iv, data, len, 1);
    
    return len;
}

static int aes_decrypt(struct crypt *c, void *iv, void *data, int len)
{
    do_aes(c, iv, data, len, 0);
    
    return len;
}

static int aes_aead_encrypt(struct crypt *c, void *iv, void *aad, int aadlen,
                            void *data, int dlen, void *tag)
{
    struct aes_priv *p = crypt_priv(c);
    int len = aadlen;
    
    if (EVP_EncryptInit_ex(p->ap_ctx, NULL, NULL, p->ap_key, iv) != 1)
        printf("EVP_EncryptInit_ex: error");
    
    if (EVP_EncryptUpdate(p->ap_ctx, NULL, &len, aad, aadlen) != 1)
        printf("EVP_EncryptUpdate: error");
    
    assert(len == aadlen);
    
    len = dlen;
    
    if (EVP_EncryptUpdate(p->ap_ctx, data, &len, data, dlen) != 1)
        printf("EVP_EncryptUpdate: error");
    
    assert(len == dlen);
    
    len = 0;
    if (EVP_EncryptFinal_ex(p->ap_ctx, data + dlen, &len) != 1)
        printf("EVP_EncryptFinal_ex: error");
    
    assert(len == 0);
    
    if (EVP_CIPHER_CTX_ctrl(p->ap_ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
        printf("EVP_CIPHER_CTX_ctrl - EVP_CTRL_GCM_GET_TAG: error");
    
    return dlen;
}

static int aes_aead_decrypt(struct crypt *c, void *iv, void *aad, int aadlen,
                            void *data, int dlen, void *tag)
{
    struct aes_priv *p = crypt_priv(c);
    int len = aadlen;
    
    if (EVP_DecryptInit_ex(p->ap_ctx, NULL, NULL, p->ap_key, iv) != 1)
        printf("EVP_EncryptInit_ex: error");
    
    if (EVP_DecryptUpdate(p->ap_ctx, NULL, &len, aad, aadlen) != 1)
        printf("EVP_EncryptUpdate: error");
    
    assert(len == aadlen);
    
    len = dlen;
    
    if (EVP_DecryptUpdate(p->ap_ctx, data, &len, data, dlen) != 1)
        printf("EVP_EncryptUpdate: error");
    
    assert(len == dlen);
    
    if (EVP_CIPHER_CTX_ctrl(p->ap_ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) != 1)
        printf("EVP_CIPHER_CTX_ctrl - EVP_CTRL_GCM_GET_TAG: error");
    
    len = 0;
    if (EVP_DecryptFinal_ex(p->ap_ctx, data + dlen, &len) <= 0)
        return -1;
    
    return dlen;
}

static struct crypt *crypt_AES_new(const EVP_CIPHER *evp)
{
    struct aes_priv *p;
    struct crypt *c;
    
    c = crypt_init(sizeof(*p));
    c->c_destroy      = aes_destroy;
    c->c_set_key      = aes_set_key;
    c->c_mac          = aes_ack_mac;
    c->c_encrypt      = aes_encrypt;
    c->c_decrypt      = aes_decrypt;
    c->c_aead_encrypt = aes_aead_encrypt;
    c->c_aead_decrypt = aes_aead_decrypt;
    
    p = crypt_priv(c);
    
    p->ap_ctx = EVP_CIPHER_CTX_new();
    if (!p->ap_ctx)
        printf("EVP_CIPHER_CTX_new: error");
    
    if (EVP_EncryptInit_ex(p->ap_ctx, evp, NULL, NULL, NULL) != 1)
        printf("EVP_EncryptInit_ex: error");
    
    if (EVP_CIPHER_CTX_ctrl(p->ap_ctx, EVP_CTRL_GCM_SET_IVLEN, 8, NULL) != 1)
        printf("EVP_CIPHER_CTX_ctrl - EVP_CTRL_GCM_SET_IVLEN: error");
    
    return c;
}

struct crypt *crypt_AES128_new(void)
{
    return crypt_AES_new(EVP_aes_128_gcm());
}

struct crypt *crypt_AES256_new(void)
{
    return crypt_AES_new(EVP_aes_256_gcm());
}
