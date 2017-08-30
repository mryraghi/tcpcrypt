//
//  checksum.h
//  tcpcrypt
//
//  Created by Romeo Bellon.
//  Copyright © 2017 Romeo Bellon. All rights reserved.
//

#ifndef checksum_h
#define checksum_h

#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <libkern/libkern.h>

extern void checksum_tcp (struct ip *ip, struct tcphdr *tcp);
extern void checksum_ip (struct ip *ip);

#endif /* checksum_h */
