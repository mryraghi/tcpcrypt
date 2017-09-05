//
//  ctl.h
//  Tcpcrypt
//
//  Created by Romeo Bellon.
//  Copyright © 2017 Romeo Bellon. All rights reserved.
//

#ifndef ctl_h
#define ctl_h

#include <sys/kern_control.h>

#include "tcpcrypt.h"
#include "common.h"
#include <string.h>

/**
 The ctl structure is used to track socket control requests to the kernel extension. Multiple
 processes could communicate with this socket filter and express an interest in contolling some
 aspect of the filter and/or requesting that the filter return connection information which this
 socket filter tracks.
 */
struct ctl {
    kern_ctl_ref        c_ref;  // control reference to the connected process
    u_int32_t           c_pid; // process identifier
    u_int32_t           c_unit; // unit number associated with the connected process
    u_int32_t           c_magic; // magic value to ensure that system is passing the right buffer
    boolean_t           c_connected;
};

int ctl_send_to_client(struct tcpcrypt_info *ti, enum ctl_action action);
void free_ctl(void);

extern struct kern_ctl_reg ctl_reg;

int ctl_connect(kern_ctl_ref ctl_ref, struct sockaddr_ctl *sac, void **unitinfo);
errno_t ctl_disconnect(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo);
int ctl_get(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t *len);
int ctl_set(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len);

#endif /* ctl_h */
