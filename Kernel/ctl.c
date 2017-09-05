//
//  ctl.c
//  Tcpcrypt
//
//  Created by Romeo Bellon.
//  Copyright © 2017 Romeo Bellon. All rights reserved.
//

#include "ctl.h"

#define CTL_MAGIC 0xDDCCBBAA
struct ctl *ctl;
boolean_t connected = FALSE;
OSMallocTag malloc_tag;

int ctl_send_to_client(struct tcpcrypt_info *ti, enum ctl_action action)
{
    int result = 0;
    size_t remaining = 0;
    struct ctl_data ctl_data = { .c_action = action, .c_ti = *ti};
    
    if (0 != (result = ctl_getenqueuespace(ctl->c_ref, ctl->c_unit, &remaining)))
        printf("ctl_send_to_client: ctl_getenqueuespace returned %d\n", result);
    
    printf("ctl_send_to_client: remaining space in queue: %d\n", (int)remaining);
    
    if (sizeof(ctl_data) <= remaining)
    {
        if (0 != (result = ctl_enqueuedata(ctl->c_ref, ctl->c_unit, &ctl_data,
                                           sizeof(ctl_data), CTL_DATA_EOR)))
        {
            switch (result) {
                case EINVAL:
                    printf("ctl_send_to_client: ctl_enqueuembuf returned EINVAL "
                           "[invalid parameters]\n");
                    break;
                    
                case ENOBUFS:
                    printf("ctl_send_to_client: ctl_enqueuedata returned ENOBUFS "
                           "[queue is full or there are no free mbufs]\n");
                    break;
                    
                default:
                    printf("ctl_send_to_client: ctl_enqueuedata returned %d\n", result);
                    break;
            }
        }
    }
    
    return result;
}

/**
 Get the ctl struct from unitinfo.
 
 @param unitinfo The unitinfo value specified by the connect function.
 @return <#return value description#>
 */
static struct ctl * ctl_unitinfo(void *unitinfo)
{
    struct ctl *result;
    result = (struct ctl *) unitinfo;
    assert(result != NULL);
    assert(result->magic == CTL_MAGIC);
    return result;
}

/**
 Called whenever a client connects to the kernel control.
 
 @param ctl_ref <#ctl_ref description#>
 @param sac <#sac description#>
 @param unitinfo <#unitinfo description#>
 @return <#return value description#>
 */
int ctl_connect(kern_ctl_ref ctl_ref, struct sockaddr_ctl *sac, void **unitinfo)
{
    printf("--> process with PID %d connected, unit %d\n", proc_selfpid(), sac->sc_unit);
    
    errno_t error = 0;
    
    // accept one client at a time
    if (connected) return EBUSY;
    
    ctl = (struct ctl *)OSMalloc(sizeof (struct ctl), malloc_tag);
    if (ctl == NULL)
    {
        printf("add_ctl_unit: OSMalloc error occurred \n");
        error = ENOMEM;
    }
    
    if (0 == error) {
        bzero(ctl, sizeof (struct ctl));
        
        ctl->c_pid = proc_selfpid();
        ctl->c_unit = sac->sc_unit;
        ctl->c_ref = ctl_ref;
        ctl->c_magic = CTL_MAGIC;
        ctl->c_connected = TRUE;
        
        connected = TRUE;
    }
    
    return error;
}

/**
 The ctl_disconnect_func is used to receive notification that a client has disconnected from the
 kernel control. This usually happens when the socket is closed. If this is the last socket attached
 to your kernel control, you may unregister your kernel control from this callback.
 
 @param ctl_ref The control ref for the kernel control instance the client has disconnected from.
 @param unit The unit number of the kernel control instance the client has disconnected from.
 @param unitinfo The unitinfo value specified by the connect function.
 @return <#return value description#>
 */
errno_t ctl_disconnect(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo)
{
    printf("process with pid=%d disconnected\n", proc_selfpid());
    
    if (ctl->c_pid == proc_selfpid())
    {
        OSFree(ctl, sizeof(struct ctl), malloc_tag);
        ctl = NULL;
        connected = FALSE;
    }
    
    return 0;
}

int ctl_send(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, mbuf_t m, int flags)
{
    int error = 0;
    mbuf_t old_packet = m;
    uint32_t packet_bytes = 0;
    unsigned char packet[CTL_RCV_BUFFER_SIZE];
    struct tcpcrypt_info *ti;
    
    // get length of packet
    do
    {
        packet_bytes += mbuf_len(old_packet);
        old_packet = mbuf_next(old_packet);
    } while (old_packet != NULL);

    
    // zero packet
    bzero(&packet, packet_bytes);
    
    printf("ctl_send... %d\n", packet_bytes);
    
    if (mbuf_flags(m) & MBUF_EXT)
        printf("has external storage\n");
    
    // copy data to local buffer
    if (0 != (error = mbuf_copydata(m, 0, packet_bytes, packet)))
        printf("ERROR - mbuf_copydata returned %d\n", error);
    
    ti = (struct tcpcrypt_info *) packet;
    
    printf("ctl_send mbuf data algo %u\n", ti->ti_ciphers_sym->sc_algo);
    
    mbuf_freem(m);
    
    return error;
}

/**
 The ctl_getopt_func is used to handle client get socket option requests for the SYSPROTO_CONTROL
 option level. A buffer is allocated for storage and passed to the function. The length of that
 buffer is also passed. Upon return, you should set *len to length of the buffer used. In some
 cases, data may be NULL. When this happens, *len should be set to the length you would have
 returned had data not been NULL. If the buffer is too small, return an error.
 
 @param ctl_ref The control ref of the kernel control.
 @param unit The unit number of the kernel control instance.
 @param unitinfo The unitinfo value specified by the connect function when the client connected.
 @param opt The socket option.
 @param data A buffer to copy the results in to. May be NULL, see discussion.
 @param len A pointer to the length of the buffer. This should be set to the length of the buffer
 used before returning.
 @return <#return value description#>
 */
int ctl_get(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data,
            size_t *len)
{
    int error = 0;
    size_t valsize = 0;
    void *buf;
    
    printf("ctl_get: opt is %d\n", opt);
    
    switch (opt) {
            //        case TCPLOGGER_STATS:
            //            valsize = min(sizeof(tl_stats), *len);
            //            buf = &tl_stats;
            //            break;
            //
            //        case TCPLOGGER_QMAX:
            //            valsize = min(sizeof(tl_stats.tls_qmax), *len);
            //            buf = &tl_stats.tls_qmax;
            //            break;
            //
            //        case TCPLOGGER_ENABLED:
            //            valsize = min(sizeof(tl_stats.tls_enabled), *len);
            //            buf = &tl_stats.tls_enabled;
            //            break;
            //
            //        case TCPLOGGER_LOG:
            //            valsize = min(sizeof(tl_stats.tls_log), *len);
            //            buf = &tl_stats.tls_log;
            //            break;
            //
        default:
            error = ENOTSUP;
            break;
    }
    
    //    if (error == 0) {
    //        *len = valsize;
    //        if (data != NULL)
    //            bcopy(buf, data, valsize);
    //    }
    
    return error;
}

/**
 The ctl_setopt_func is used to handle set socket option calls for the SYSPROTO_CONTROL option
 level.
 
 @param ctl_ref The control ref of the kernel control.
 @param unit The unit number of the kernel control instance.
 @param unitinfo The unitinfo value specified by the connect function when the client connected.
 @param opt The socket option.
 @param data A pointer to the socket option data. The data has already been copied in to the kernel
 for you.
 @param len The length of the socket option data.
 @return <#return value description#>
 */
int ctl_set(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len)
{
    int error = 0;
    enum ctl_action action = (enum ctl_action) opt;
    
    switch (action)
    {
        case INIT_TI:
        {
            struct tcpcrypt_info *ti = (struct tcpcrypt_info *)OSMalloc(sizeof(data), malloc_tag);
            ti = (struct tcpcrypt_info *) data;
            printf("ctl_set: received setsockopt INIT_TI, algo %d\n", ti->ti_ciphers_sym->sc_algo);
            OSFree(ti, sizeof(ti), malloc_tag);
            break;
        }
            
        default:
            printf("ctl_set - action is %d\n", action);
            error = ENOTSUP;
            break;
    }
    
    return error;
}

void free_ctl(void)
{
    if (ctl)
    {
        OSFree(ctl, sizeof(struct ctl), malloc_tag);
        ctl = NULL;
        connected = FALSE;
    }
}

struct kern_ctl_reg ctl_reg = {
    TCPCRYPT_BUNDLE_ID,
    0,                  // set to 0 for dynamically assigned ctl ID, CTL_FLAG_REG_ID_UNIT not set
    0,                  // ctl_unit - ignored when CTL_FLAG_REG_ID_UNIT not set
    CTL_FLAG_PRIVILEGED,    // privileged access required to access this filter
    CTL_SEND_BUFFER_SIZE,   // use default send size buffer
    CTL_RCV_BUFFER_SIZE,    // override receive buffer size
    ctl_connect,        // called when a connection request is accepted
    ctl_disconnect,     // called when a connection becomes disconnected
    ctl_send,           // ctl_send_func - handles data sent from the client to kernel control
    ctl_set,            // called when the user process makes the setsockopt call
    ctl_get             // called when the user process makes the getsockopt call
};
