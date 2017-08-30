//
//  checksum.c
//  tcpcrypt
//
//  Created by Romeo Bellon on 23/07/2017.
//  Copyright © 2017 Romeo Bellon. All rights reserved.
//

#include "checksum.h"

struct tcp_ph {
    struct in_addr  ph_src;
    struct in_addr  ph_dst;
    uint8_t         ph_zero;
    uint8_t         ph_proto;
    uint16_t        ph_len;
};

static unsigned short checksum(struct tcp_ph *ph, unsigned short *ptr, int nbytes, int s)
{
    register long sum;
    u_short oddbyte;
    register u_short answer;
    
    sum = s;
    
    if (ph) {
        unsigned short *p = (unsigned short*) ph;
        int i;
        
        for (i = 0; i < sizeof(*ph) >> 1; i++)
            sum += *p++;
    }
    
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }
    
    if (nbytes == 1)
    {
        oddbyte = 0;
        *((u_char *) & oddbyte) = *(u_char *) ptr;
        sum += oddbyte;
    }
    
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return (answer);
}

void checksum_ip(struct ip *ip)
{
    ip->ip_sum = 0;
    ip->ip_sum = checksum(NULL, (unsigned short*) ip, sizeof(*ip), 0);
}

void checksum_tcp(struct ip *ip, struct tcphdr *tcp)
{
    struct tcp_ph ph;
    int len, sum = 0;
    
    len = ntohs(ip->ip_len) - (ip->ip_hl << 2);
    
    ph.ph_src   = ip->ip_src;
    ph.ph_dst   = ip->ip_dst;
    ph.ph_zero  = 0;
    ph.ph_proto = ip->ip_p;
    ph.ph_len   = htons(len);
    
    if (sum != 0)
        len = tcp->th_off << 2;
    
    tcp->th_sum = 0;
    tcp->th_sum = checksum(&ph, (unsigned short*) tcp, len, sum);
}
