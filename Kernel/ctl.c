//
//  ctl.c
//  Tcpcrypt
//
//  Created by Romeo Bellon.
//  Copyright © 2017 Romeo Bellon. All rights reserved.
//

#include "ctl.h"

#define CTL_MAGIC 0xDDCCBBAA

struct ctl_list_head ctl_list;

/**
 Remove ctl struct from ctl_list.

 @param ctl The ctl to be removed.
 @return <#return value description#>
 */
static int del_ctl_unit_locked(struct ctl * ctl)
{
    printf("del_ctl_unit_locked: will unregister unit %d\n", ctl->c_unit);
    
    TAILQ_REMOVE(&ctl_list, ctl, c_link);
    OSFree(ctl, sizeof(struct ctl), malloc_tag);
//    tl_stats.tls_ctl_connected--;    // decrement the connected counter
    
    return 0;
}

static int del_ctl_unit(struct ctl * ctl)
{
    int error;
    
    // printf("del_ctl_unit entered tl_cb is at 0x%X\n", tl_cb);
    
    lck_mtx_lock(ctl_list_mutex);
    
    error = del_ctl_unit_locked(ctl);
    
    lck_mtx_unlock(ctl_list_mutex);
    
    return error;
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
    printf("process with PID %d connected, unit %d\n", proc_selfpid(), sac->sc_unit);
    
    errno_t error = 0;
    
    // accept one client at a time
    if (ctl != NULL) return EBUSY;
    
    ctl = (struct ctl *)OSMalloc(sizeof (struct ctl), malloc_tag);
    if (ctl == NULL)
    {
        printf("add_ctl_unit: OSMalloc error occurred \n");
        error = ENOMEM;
    }
    
    if (0 == error) {
        bzero(ctl, sizeof (struct ctl));
        
        ctl->c_unit = sac->sc_unit;
        ctl->c_ref = ctl_ref;
        ctl->c_magic = CTL_MAGIC;
        ctl->c_connected = TRUE;
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
    
    OSFree(ctl, sizeof(struct ctl), malloc_tag);
    ctl = NULL;
    
    return 0;
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
    
    if (error == 0) {
        *len = valsize;
        if (data != NULL)
            bcopy(buf, data, valsize);
    }
    
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
    int intval;
    
    printf("ctl_set - opt is %d\n", opt);
    
    switch (opt)
    {
//        case TCPLOGGER_QMAX:
//            if (len < sizeof(int)) {
//                error = EINVAL;
//                break;
//            }
//            intval = *(int *)data;
//
//            lck_mtx_lock(gmutex);
//            if (intval >= 0)
//                tl_stats.tls_qmax = intval;
//            else
//                tl_stats.tls_qmax = TCPLOGGER_QMAX_DEFAULT;
//            lck_mtx_unlock(gmutex);
//            break;
//
//        case TCPLOGGER_ENABLED:
//            if (len < sizeof(int)) {
//                error = EINVAL;
//                break;
//            }
//            intval = *(int *)data;
//            lck_mtx_lock(gmutex);
//            tl_stats.tls_enabled = intval ? 1 : 0;
//            lck_mtx_unlock(gmutex);
//            break;
//
//        case TCPLOGGER_LOG:
//            if (len < sizeof(int)) {
//                error = EINVAL;
//                break;
//            }
//
//            intval = *(int *)data;
//            lck_mtx_lock(gmutex);
//            tl_stats.tls_log = intval ? 1 : 0;
//            lck_mtx_unlock(gmutex);
//            break;
//
//        case TCPLOGGER_FLUSH:
//            // don't set mutex here as it will be set in tl_flush_backlog
//            tl_flush_backlog(FALSE);
//            break;
            
        default:
            error = ENOTSUP;
            break;
    }
    
    return error;
}


struct kern_ctl_reg ctl_reg = {
    TCPCRYPT_BUNDLE_ID,
    0,                  // set to 0 for dynamically assigned ctl ID, CTL_FLAG_REG_ID_UNIT not set
    0,                  // ctl_unit - ignored when CTL_FLAG_REG_ID_UNIT not set
    CTL_FLAG_PRIVILEGED,// privileged access required to access this filter
    0,                  // use default send size buffer
    (8 * 1024),         // override receive buffer size
    ctl_connect,        // called when a connection request is accepted
    ctl_disconnect,     // called when a connection becomes disconnected
    NULL,               // ctl_send_func - handles data sent from the client to kernel control
    ctl_set,            // called when the user process makes the setsockopt call
    ctl_get             // called when the user process makes the getsockopt call
};
