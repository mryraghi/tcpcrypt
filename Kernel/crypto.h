//
//  crypto.h
//  tcpcrypt
//
//  Created by Romeo Bellon on 23/07/2017.
//  Copyright © 2017 Romeo Bellon. All rights reserved.
//

#ifndef crypto_h
#define crypto_h

#include <sys/types.h>
#include <sys/_types/_iovec_t.h>
#include <sys/queue.h>

#include "tcpcrypt.h"

typedef void *(*crypt_ctr)(void);

enum {
    TYPE_PKEY = 0,
    TYPE_SYM,
};

struct cipher_list {
    TAILQ_ENTRY(cipher_list) c_next;
    u_int8_t    c_id;
    int         c_type;
    crypt_ctr   c_ctr;
};

struct ciphers {
    TAILQ_ENTRY(ciphers) c_next;
    struct cipher_list *c_cipher;
    unsigned char c_spec[4];
    int c_speclen;
};




//extern struct cipher_list *crypt_cipher_list(void);

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

extern struct crypt *crypt_HMAC_SHA256_new(void); // crypto_hmac.c
extern struct crypt *crypt_HKDF_SHA256_new(void); // crypto_hkdf.c
extern struct crypt *crypt_ECDHE256_new(void); // crypto_ecdhe.c
extern struct crypt *crypt_ECDHE521_new(void); // crypto_ecdhe.c
extern struct crypt *crypt_AES128_new(void); // crypto_aes.c
extern struct crypt *crypt_AES256_new(void); // crypto_aes.c

extern void crypt_register(int type, uint8_t id, crypt_ctr ctr);
extern struct crypt *crypt_init(int sz);

#endif /* crypto_h */
