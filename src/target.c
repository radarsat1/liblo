/*
 *  Copyright (C) 2004 Steve Harris
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  $Id$
 */

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "lo_types_internal.h"
#include "lo/lo.h"

lo_target lo_target_new(const char *address, const char *port)
{
    return lo_address_new(address, port);
}

void lo_target_free(lo_target t)
{
    lo_address_free(t);
}

int lo_target_errno(lo_target t)
{
    return t->errnum;
}

const char *lo_target_errstr(lo_target t)
{
    char *msg;

    if (t->errstr) {
	return t->errstr;
    }

    msg = strerror(t->errnum);
    if (msg) {
	return msg;
    } else {
	return "unknown error";
    }

    return "unknown error";
}

/* vi:set ts=8 sts=4 sw=4: */
