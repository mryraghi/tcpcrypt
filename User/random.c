//
//  random.c
//  tcpcrypt
//
//  Created by Romeo Bellon.
//  Copyright © 2017 Romeo Bellon. All rights reserved.
//

#include "random.h"
#include <openssl/rand.h>
#include <openssl/err.h>

unsigned char getRandomByte()
{
    unsigned char buffer;
    unsigned long err;
    int rc;
    
    
    rc = RAND_bytes(&buffer, sizeof(buffer));
    err = ERR_get_error();
    
    if(rc != 1) {
        /* RAND_bytes failed */
        /* `err` is valid    */
    }
    
    printf("random byte: %c", buffer);
    
    return buffer;
}
