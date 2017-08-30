//
//  ctl.h
//  Tcpcrypt
//
//  Created by Romeo Bellon on 27/08/2017.
//  Copyright © 2017 Romeo Bellon. All rights reserved.
//

#ifndef ctl_h
#define ctl_h

#include <sys/kern_control.h>
#include "tcpcrypt.h"

/**
 The ctl structure is used to track socket control requests to the kernel extension. Multiple
 processes could communicate with this socket filter and express an interest in contolling some
 aspect of the filter and/or requesting that the filter return connection information which this
 socket filter tracks.
 */
struct ctl {
    TAILQ_ENTRY(ctl)  c_link; // link to next control block record or NULL if end of chain.
    kern_ctl_ref        c_ref;  // control reference to the connected process
    u_int32_t           c_unit; // unit number associated with the connected process
    u_int32_t           c_magic;  /* magic value to ensure that system is passing me my buffer */
    boolean_t           c_connected;
};

extern struct ctl *ctl;

/**
 Definition of queue to store control block references. As each interested client connects to this
 socket filter, a tl_cb structure is allocated to store information about the connected process.
 */
extern TAILQ_HEAD(ctl_list_head, ctl) ctl_list;

extern kern_ctl_ref ctl_ref;
extern struct kern_ctl_reg ctl_reg;

extern int ctl_connect(kern_ctl_ref ctl_ref, struct sockaddr_ctl *sac, void **unitinfo);
extern errno_t ctl_disconnect(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo);
extern int ctl_get(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data,
                   size_t *len);
extern int ctl_set(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data,
                   size_t len);

#endif /* ctl_h */
