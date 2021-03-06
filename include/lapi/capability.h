/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2019 Richard Palethorpe <rpalethorpe@suse.com>
 */

#ifndef LAPI_CAPABILITY_H
#define LAPI_CAPABILITY_H

#include "config.h"

#ifdef HAVE_SYS_CAPABILITY_H
# include <sys/capability.h>
#endif

#ifndef CAP_NET_RAW
# define CAP_NET_RAW          13
#endif

#ifndef CAP_SYS_ADMIN
# define CAP_SYS_ADMIN        21
#endif

#ifndef CAP_AUDIT_READ
# define CAP_AUDIT_READ       37
#endif

#ifndef CAP_TO_INDEX
# define CAP_TO_INDEX(x)     ((x) >> 5)
#endif

#ifndef CAP_TO_MASK
# define CAP_TO_MASK(x)      (1 << ((x) & 31))
#endif

#endif
